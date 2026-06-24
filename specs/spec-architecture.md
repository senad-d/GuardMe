# Plan: GuardMe Architecture

## Task Description

Design the architecture for GuardMe, a TypeScript Pi extension package that enforces IAM-like allow/deny policy for LLM tool calls inside Pi sessions. GuardMe protects shell commands, generated script/file content, local script execution, and local file access by evaluating built-in Pi tool calls before execution, using global and project-local YAML policy files, a balanced segment-aware command allowlist model, and separate JSONL state for warned-once and policy-missing behavior.

## Objective

Provide a development blueprint for implementing GuardMe without relying on OS sandboxing. The finished extension should guard Pi LLM tool calls for shell commands, script-writing trampolines, local script execution, file reads, writes/edits, deletes/renames/moves, and file discovery while preserving a clear deny-first, segment-aware command allowlist policy model with user-controlled TUI approval flow.

## Problem Statement

Pi intentionally runs with the permissions of the local user and does not provide a built-in sandbox. Built-in tools such as `bash`, `read`, `write`, `edit`, `grep`, `find`, and `ls` can access the local filesystem and execute commands inside the user's normal trust boundary. GuardMe must reduce unintended access within Pi sessions by enforcing a policy layer before LLM-requested tool calls run.

The current implementation blocks many direct credential and cloud-CLI forms, but it still has two important bypass classes that this architecture must close:

- The LLM can write a script or helper file containing forbidden commands and then execute that script with a generic-looking command.
- Generic commands such as browser launchers or newly created executables can run when they are not present in either `allowCommands` or `denyCommands`.

GuardMe is not an OS-level security boundary. It can only enforce actions routed through Pi extension hooks and overridden/observed Pi tools. Commands executed outside Pi, direct terminal use, and other processes are outside scope. Because GuardMe is not a sandbox, it must fail closed for unclassified `bash` command segments rather than assuming a generic shell command is safe.

The initial exact-allow behavior is too strict for day-to-day agent workflows: safe discovery commands such as `ls -lh`, `pwd`, `grep ...`, or `find ...` often need to run in combinations that are hard to predict ahead of time. The architecture should let users express safe command families with patterns such as `ls *` and allow compound commands only when every executable segment is allowed and no deny/protection rule matches.

## Solution Approach

GuardMe should register Pi event handlers that classify each relevant tool call, load and merge global/local policy, evaluate the call against deny-first rules, and return `{ block: true, reason }` when a call must not run. In addition to command-line classification, `write`/`edit` payloads that create executable scripts or command-bearing files must be inspected before the file is written, and `bash` calls that execute local scripts must inspect the script content before execution when the file is readable through policy.

Command evaluation should be segment-aware. A compound shell command such as `pwd && ls -lh` should be split into executable segments, each segment should be checked against hard-deny/path/script protections first, and the full command should run only when every segment is explicitly allowed by an acceptable `allowCommands` rule. Wildcard command rules can allow safe command families such as `ls *`, `pwd *`, `grep *`, or `find *`, but they cannot override hard denials, protected paths, outside-project path requirements, dangerous/destructive actions, or uninspectable script content.

For dangerous-but-not-hard-forbidden or policy-missing actions, the first attempt should be blocked with model-facing coaching feedback and recorded in JSONL state; repeated attempts of the same normalized command/action/segment type should present a TUI approval flow when UI is available. User decisions can be one-time or persisted to global/local YAML. Hard-denied and existing deny-rule matches remain non-overridable and do not offer an allow choice.

Key Pi APIs and documented constraints:

- Use `pi.on("tool_call", ...)` to inspect and block tool calls before execution.
- `event.input` may be inspected and, if needed, patched before execution; GuardMe should prefer block/allow over mutation.
- Use `ctx.cwd` as the active project root and `ctx.hasUI` / `ctx.mode` before prompting.
- Use `ctx.ui.custom()` for the polished TUI modal in TUI mode; use simpler `ctx.ui.select()` fallback for RPC/UI-capable non-TUI if needed.
- In non-UI modes, prompt-needed decisions must fail closed.
- Keep `src/extension.ts` small and delegate to `register*` modules.
- Do not start file watchers, timers, sockets, or background jobs in the extension factory.
- If future mutating custom tools are added, use Pi file mutation queue helpers and safe path resolution.

## Relevant Files

Existing files to update during implementation:

- `src/extension.ts` - Keep as the small extension entry point; import and call registration functions only.
- `src/constants.ts` - Project constants such as display name, status key, command name, config filenames, state filenames, and policy version.
- `src/events/` - Register lifecycle, policy guidance, and `tool_call` enforcement handlers.
- `src/commands/` - Register `/guardme` status/setup/help command.
- `src/tools/` - No LLM-facing custom tool is planned initially; leave empty unless a future spec adds one.
- `test/` - Pure unit tests and integration tests for policy behavior.
- `README.md`, `SECURITY.md`, `docs/STRUCTURE.md` - Keep security model and limitations visible.
- `package.json` - Keep Pi core packages in `peerDependencies` with `"*"`; add non-Pi runtime libraries to `dependencies` only when implementation imports them.

### New Files

Create these implementation files when feature work begins:

- `src/config/schema.ts` - TypeScript types and validation helpers for GuardMe YAML policy.
- `src/config/load-config.ts` - Load global and local YAML, apply built-in defaults, merge arrays, and report config diagnostics.
- `src/config/write-policy.ts` - Persist user-selected allow/deny rules to global/local YAML without weakening hard protections.
- `src/state/warnings.ts` - Append/read JSONL warning state for first-time dangerous-action fingerprints.
- `src/policy/action.ts` - Domain model for action kinds (`read`, `list`, `write`, `edit`, `delete`, `rename`, `move`, `shell`).
- `src/policy/paths.ts` - Safe path resolution, project-boundary checks, glob matching, and symlink-aware canonicalization.
- `src/policy/commands.ts` - Shell command classifier for hard-denied, dangerous, policy-missing, and policy-checkable command patterns.
- `src/policy/script-content.ts` - Extract and classify command-bearing content from proposed file writes/edits and local scripts before those files are written or executed.
- `src/policy/evaluate.ts` - Central policy decision engine with deny-first, segment-aware command allowlist, and policy-missing precedence.
- `src/events/register-guard.ts` - Main `tool_call` guard registration, including write/edit content scanning and local-script execution inspection.
- `src/events/register-guidance.ts` - Model-facing guidance injection for blocked/coached/policy-missing actions.
- `src/events/register-lifecycle.ts` - Session status, config load diagnostics, cleanup.
- `src/ui/approval-modal.ts` - TUI/RPC-capable user approval flow.
- `src/ui/render-policy-summary.ts` - Shared formatting for status and modal summaries.
- `src/commands/guardme-command.ts` - `/guardme` command for status, setup, paths, and diagnostics.
- `docs/POLICY.md` - User-facing YAML policy reference.
- `docs/VALIDATION.md` - Validation and isolated smoke-test guide.

## Architecture Details

### Pi integration surface

| Surface | Name | Purpose | Notes |
| --- | --- | --- | --- |
| Command | `/guardme` | Show status, config paths, merged policy summary, setup/help | Implement after config/policy modules exist |
| Event | `tool_call` | Enforce policy before LLM tool calls execute | Must cover `bash`, `read`, `write`, `edit`, `grep`, `find`, `ls` |
| Event | `before_agent_start` | Add policy guidance after recorded blocked/coached/policy-missing events | Keep concise; do not leak sensitive paths or command output |
| Event | `session_start` | Load/validate policy, reconstruct warning state, set status | No background jobs |
| Event | `session_shutdown` | Clear status and release in-memory state | No persistent processes |
| UI | approval modal | Ask user to allow/deny and optionally persist rule | TUI first, non-UI fail closed |
| Resource | none | No skill/prompt/theme resources planned | Keep package focused |

### Policy precedence

GuardMe should use explicit deny-first and segment-aware command-default-deny evaluation:

1. Built-in hard denials always block:
   - cloud CLIs: `aws`, `az`, `gcloud`, and common aliases/subcommands
   - disk formatting or raw disk operations such as `diskutil eraseDisk`, `mkfs`, `fdisk`, `dd` to block devices
   - deleting `.git`
   - reading environment/credential files, SSH keys, and cloud credential directories
   - generated scripts or command-bearing file edits that contain hard-denied commands or credential paths
2. `zeroAccessPaths` block every action, including read/list/write/delete and content-derived shell access.
3. `readOnlyPaths` allow read/list but block write/edit/delete/move/rename.
4. `noDeletePaths` block delete/move/rename-destructive operations.
5. `denyPaths` and `denyCommands` block matching actions.
6. Proposed `write`/`edit` content is scanned before the target file is mutated. If extracted commands would be denied, hard-denied, dangerous, or policy-missing, the write/edit is blocked before any file is changed.
7. `bash` commands that execute local scripts or generated executables are inspected before execution. If the script content contains denied/hard-denied commands, or contains unclassified commands without an allow rule, execution is blocked.
8. Outside-project path access is denied unless an explicit path allow/read-only rule permits the action.
9. `allowPaths` and segment-aware `allowCommands` may allow actions only if no deny/hard/protection/outside-project/content-derived rule matched. A compound `bash` command is allowed only when every executable segment is allowed by an acceptable command rule or a narrower exact full-command rule. Wildcard command rules may authorize non-dangerous generic/read/list/write/edit segments after path checks; exact command rules are still required for dangerous, destructive, delete, move, or rename behavior.
10. Dangerous or policy-missing commands/actions use warned-once behavior:
    - first fingerprint/type: block with coaching, append JSONL state, and inject model-facing guidance
    - repeated fingerprint/type: ask user if UI exists, otherwise block
    - persistent allow decisions write an explicit `allowCommands` or path allow rule; persistent block decisions write an explicit deny rule
11. Built-in default project policy applies only to direct path actions when no explicit rule matches:
    - reads/lists/writes/edits inside `ctx.cwd` allowed unless denied/protected/content-derived checks fail
    - deletes inside project require stricter dangerous/destructive analysis
    - outside-project reads require explicit `allowPaths` or `readOnlyPaths`
    - outside-project writes/deletes/moves/renames require explicit allow and must not hit any hard/protected rule
12. Generic `bash` command segments are not allowed merely because they are low-risk or unknown. Every executable segment in a shell command must match an allow rule, a known safe built-in default allow, or a user approval decision before the full command can run. If any segment is missing policy, the whole command is blocked with guidance and the missing segment is used for warned-once state.

### Config model

Policy files:

- Global base: `~/.pi/agent/guardme.yaml`
- Project overlay: `.pi/agent/guardme.yaml`

On package installation, GuardMe should create the global policy file with sensible defaults if it is missing and must not overwrite an existing file. If config files are later missing at runtime, GuardMe should still run with built-in safe defaults. Project-local YAML should be created only when the user saves a rule or explicitly runs setup.

Proposed YAML shape:

```yaml
version: 1

allowPaths:
  - pattern: "src/**"
    actions: [read, list, write, edit]
    reason: "Project source files"

denyPaths:
  - pattern: "**/.env"
    actions: [read, list, write, edit, delete, move, rename]
    reason: "Environment files may contain credentials"
  - pattern: "**/.env.*"
    actions: [delete, move, rename]
    reason: "Environment template files can be read or edited, but destructive changes require review"

zeroAccessPaths:
  - pattern: "~/.ssh/**"
    reason: "SSH keys are never available to the LLM"

readOnlyPaths:
  - pattern: "docs/**"
    reason: "Documentation can be read but not edited by default"

noDeletePaths:
  - pattern: ".git/**"
    reason: "Repository metadata must not be deleted"

allowCommands:
  - pattern: "npm run test*"
    reason: "Project validation"

denyCommands:
  - pattern: "sudo *"
    reason: "Privilege escalation is blocked"

dangerousCommands:
  - pattern: "rm -rf *"
    reason: "Recursive deletion requires coaching/user approval"

protectedCredentialPaths:
  - pattern: "~/.aws/**"
  - pattern: "~/.config/gcloud/**"
  - pattern: "~/.azure/**"
```

Implementation notes:

- Patterns should support glob syntax.
- Match against canonical absolute paths and project-relative paths where appropriate.
- Expand `~` against the current user home directory.
- Strip leading `@` from model-supplied path arguments, matching Pi built-in path behavior.
- Merge global then local arrays by union; keep source metadata for diagnostics.
- Local policy can add restrictions but cannot weaken global denials/hard protections.
- `allowCommands` is an explicit command allowlist evaluated against normalized shell command segments as well as exact whole-command text where appropriate. Generic `bash` command segments that do not match `allowCommands`, `denyCommands`, or a built-in hard/dangerous classifier must be treated as policy-missing and blocked on the first attempt.
- A trailing argument wildcard pattern such as `pwd *` or `ls *` should be documented and implemented as a user-friendly zero-or-more-arguments match, so it matches both `pwd` and `pwd -L`, or both `ls` and `ls -lh`.
- Persistent user approval for a policy-missing command should save the narrowest exact `allowCommands` or `denyCommands` rule practical for the missing segment, not a broad wildcard.
- Invalid config should be reported clearly and fail closed for affected ambiguous rules.

### State model

State files:

- Global: `~/.pi/agent/guardme-state.jsonl`
- Project: `.pi/agent/guardme-state.jsonl`

Use JSONL append-only records so warnings survive sessions and can be audited without mixing generated state into hand-written YAML policy.

Proposed records:

```json
{"type":"warning","version":1,"timestamp":"2026-06-21T00:00:00.000Z","fingerprint":"sha256:...","scope":"project","cwd":"/path/to/project","toolName":"bash","action":"delete","risk":"dangerous","target":"rm -rf build","count":1,"reasonCode":"dangerous-command"}
{"type":"warning","version":1,"timestamp":"2026-06-21T00:00:30.000Z","fingerprint":"sha256:...","scope":"project","cwd":"/path/to/project","toolName":"write","action":"write","risk":"medium","target":"script content invokes unapproved command: brave","count":1,"reasonCode":"policy-missing-command"}
{"type":"decision","version":1,"timestamp":"2026-06-21T00:01:00.000Z","fingerprint":"sha256:...","scope":"global","decision":"deny","persistedTo":"global-yaml","reason":"User denied repeated dangerous or policy-missing action"}
```

State implementation should:

- read only relevant records for the current project/session
- tolerate malformed lines by reporting diagnostics and continuing with valid records
- append atomically enough for local use
- avoid storing secrets or full sensitive file contents
- store fingerprints over normalized action/risk/path/command metadata, not raw credential values
- store enough reason metadata (`dangerous-command`, `policy-missing-command`, `script-content-denied`, etc.) to explain repeated prompts without storing file contents

### Command and path classification

GuardMe needs deterministic classifiers:

- `read`: `read`, `grep` file targets, command patterns like `cat`, `less`, `head`, `tail` when invoked through `bash`
- `list`: `ls`, `find`, `grep` directory traversal, command patterns like `tree`
- `write/edit`: `write`, `edit`, command patterns like redirection, `tee`, `sed -i`, `python -c` file writes when detectable
- `delete`: `rm`, `rmdir`, destructive shell patterns, deleting via language commands when detectable
- `move/rename`: `mv`, `rename`, `rsync --delete` and similar when detectable
- `shell`: command execution that must match explicit allow/deny/dangerous policy; generic unknown shell commands are policy-missing, not implicitly allowed
- `script-content`: extracted command lines from shebang shell scripts, `*.sh`/`*.bash`/`*.zsh`, Makefile recipes, package manager scripts, CI `run:` blocks, Dockerfile `RUN` lines, and obvious heredoc/stdin scripts where practical
- `local-script-exec`: `./script`, `bash script.sh`, `sh script.sh`, `zsh script.zsh`, or other local executable/script invocations that should be inspected before execution

Shell parsing should be conservative and segment-oriented. Split top-level compounds, pipelines, wrapper-invoked commands, command substitutions, process substitutions, and `find -exec`/package-runner forms into executable segments where practical. If any segment cannot be safely classified, is not explicitly allowed, appears to execute a local file whose contents cannot be inspected, or appears to touch outside-project paths/destructive verbs, block the entire command with model-facing guidance on first attempt and require user approval on a repeated attempt when UI exists.

### Approval flow

The approval flow should be designed before feature implementation and implemented with Pi TUI patterns. It applies to repeated dangerous-but-not-hard-forbidden actions and repeated policy-missing commands/content. Existing deny rules and built-in hard denials still block without an allow option.

- TUI mode: custom overlay/modal with a compact table of facts and keyboard-selectable actions.
- RPC mode or UI-capable non-TUI: use `ctx.ui.select()` fallback.
- No UI: block prompt-needed actions with an explanatory reason and model-facing next-step guidance.

The modal should show:

- risk level and decision recommendation
- tool/action name
- command or path target
- project root
- matched policy rules with source (`builtin`, `global`, `local`)
- suggested safer behavior
- choices:
  - allow once
  - deny once
  - allow and save to local config
  - deny and save to local config
  - allow and save to global config
  - deny and save to global config

Persisting a saved decision must re-run policy validation and refuse to save a rule that would weaken a hard denial or existing deny/protection rule. For policy-missing command decisions, saved allow rules should be exact segment rules by default; saved deny rules should capture the normalized segment family or exact segment chosen in the modal.

### Data flow

```text
Pi loads extension
  -> guardMe(pi)
    -> registerLifecycle(pi)
    -> registerGuard(pi)
    -> registerGuidance(pi)
    -> registerGuardMeCommand(pi)

session_start
  -> resolve config/state paths from ctx.cwd
  -> load built-in defaults + global YAML + trusted local YAML
  -> read warning JSONL state
  -> set GuardMe status

tool_call
  -> ignore non-guarded tools
  -> normalize input into PolicyRequest
  -> classify action and extract candidate paths/commands
  -> for bash, split command text into executable segments and require every segment to pass deny-first checks plus command allow matching
  -> for write/edit, extract command-bearing content before mutating the file
  -> for bash local-script execution, inspect the script content before executing it
  -> evaluate hard denials, content-derived decisions, default-deny commands, and merged policy
  -> allow, block, coach, or ask user
  -> append state JSONL for dangerous or policy-missing first attempts
  -> persist YAML rule only after explicit user decision
  -> return model-facing block result or undefined

session_shutdown
  -> clear status and in-memory caches
```

### Security boundaries

- GuardMe is a Pi-session guard, not a kernel/OS sandbox.
- It does not protect direct user terminal commands or other processes.
- It should not log secret contents, command output, full file contents, or credentials.
- It may inspect proposed script/file content and local scripts for policy enforcement, but stored diagnostics/state must include only redacted snippets or normalized fingerprints.
- It must handle symlink/path traversal attempts conservatively.
- It must block hard-forbidden actions even if an allow rule matches.
- It must fail closed when policy evaluation is ambiguous for dangerous/outside-project mutations, script content, or unknown shell commands.
- It must clearly document that stronger isolation requires containers, VMs, or OS sandboxing.

## Implementation Phases

### Phase 1: Foundation

- Replace placeholders with GuardMe constants and non-functional entry point if not already done.
- Add config/state/policy domain types.
- Add YAML parsing and JSONL state helpers.
- Add pure path, command classifier, and script-content extractor tests.

### Phase 2: Core Implementation

- Implement merged policy loading and precedence.
- Implement `tool_call` guard for `bash`, `read`, `write`, `edit`, `grep`, `find`, and `ls`.
- Implement hard-denied cloud CLI, credential, `.git`, and disk-formatting rules.
- Implement segment-aware default-deny handling for shell command segments that are absent from allow/deny policy.
- Implement write/edit content scanning and local-script execution inspection.
- Implement warned-once state and coaching block behavior for dangerous and policy-missing actions.

### Phase 3: Integration & Polish

- Implement TUI approval modal and fallback prompting for repeated dangerous/policy-missing attempts.
- Implement YAML rule writer for user-saved decisions.
- Implement model-facing block guidance and `before_agent_start` guidance injection.
- Implement `/guardme` command for status/setup/help.
- Update docs and tests.
- Run validation and isolated Pi smoke test.

## Step by Step Tasks

### 1. Establish domain types

- Define policy action kinds, risk levels, rule sources, policy request/decision shapes, and config schema types.
- Keep types independent from Pi APIs so they can be unit tested.

### 2. Implement config loading and merging

- Load built-in defaults first.
- Load global YAML if present.
- Load local YAML only when project trust permits reading local policy.
- Merge arrays by union while retaining source metadata.
- Validate schema and report diagnostics.

### 3. Implement path normalization and glob matching

- Resolve relative paths against `ctx.cwd`.
- Expand `~` and strip leading `@`.
- Canonicalize existing paths using real paths and handle missing paths lexically.
- Match both absolute and project-relative forms.

### 4. Implement shell command and script-content classification

- Detect hard-denied binaries and destructive patterns.
- Extract obvious path operands for read/write/delete/move commands.
- Treat generic shell command segments absent from allow/deny/dangerous policy as policy-missing.
- Extract command-bearing content from proposed writes/edits and local script files.
- Conservatively flag ambiguous destructive/outside-project/script commands.

### 5. Implement policy evaluation

- Apply hard denial and deny-first precedence.
- Apply content-derived script decisions before path default allows.
- Apply default project path policy only to direct path actions, not generic shell commands.
- Return structured decisions with matched rule details, reason codes, and user/model-facing guidance strings.

### 6. Implement Pi event integration

- Register lifecycle, `tool_call`, and guidance handlers.
- Convert Pi built-in tool inputs into policy requests.
- Inspect write/edit content before allowing file mutation.
- Inspect local script execution before allowing `bash` to run it.
- Block, coach, prompt, or allow based on decisions.

### 7. Implement state persistence

- Append warning and decision JSONL records for dangerous and policy-missing attempts.
- Reconstruct warning counts on session start.
- Avoid storing sensitive raw values or full file content.

### 8. Implement approval UI and rule persistence

- Build the TUI modal using existing Pi TUI patterns.
- Provide select fallback for UI-capable non-TUI contexts.
- Save user decisions to local/global YAML only after validation.

### 9. Implement command, setup, and documentation

- Add `/guardme` status/setup/help.
- Make `/guardme setup` provide a TUI setup flow for global/local defaults and fully custom rules, with select/input fallback outside TUI.
- Document policy YAML, installer-created global defaults, state files, limitations, and validation commands.

### 10. Validate

- Add unit and integration tests.
- Run package checks and an isolated Pi smoke test.

## Testing Strategy

- Pure unit tests for config parsing, merging, glob matching, path normalization, command classification, script-content extraction, and policy precedence.
- Table-driven tests for hard denials: cloud CLIs, `.git` deletion, `.env`, SSH keys, credential dirs, disk formatting.
- Regression tests for generated scripts that attempt credential reads, including `write`/`edit` payloads and later `bash ./script` execution.
- Regression tests for generic commands such as browser launchers that are absent from both allow and deny rules.
- Event adapter tests using representative built-in tool inputs.
- UI behavior tests at the decision mapping level; avoid brittle terminal rendering snapshots unless necessary.
- Regression tests proving deny rules trump allow rules and local policy cannot weaken global hard protections.
- Non-UI mode tests proving prompt-needed actions block.

## Acceptance Criteria

- GuardMe enforces deny-first policy for `bash`, `read`, `write`, `edit`, `grep`, `find`, and `ls` LLM tool calls.
- Global and local YAML policies load and merge as specified.
- Hard protections always block, regardless of allow rules.
- Proposed writes/edits that contain denied, hard-denied, dangerous, or policy-missing commands are blocked before the target file is written.
- Local scripts are inspected before `bash` executes them; script content cannot bypass deny/hard protections.
- Generic `bash` command segments absent from allow/deny/dangerous policy block first with model-facing guidance instead of running by default.
- Wildcard allow rules such as `ls *` and `pwd *` can allow safe classified segments, including in compounds like `pwd && ls -lh`, after deny/protection/path checks pass.
- Compound shell commands block when any executable segment is denied, dangerous without exact allow, protected, outside-project without path allow, uninspectable, or policy-missing.
- First dangerous or policy-missing repeated-behavior fingerprint is coached and persisted to JSONL state.
- Repeated dangerous or policy-missing attempts prompt the user when UI exists and block when UI is unavailable.
- User can save allow/deny rules to global or local YAML without weakening hard protections.
- `/guardme` explains current status and config/state paths.
- Documentation clearly states Pi-session-only enforcement and no OS sandbox guarantee.

## Validation Commands

- `npm run typecheck` - Verify TypeScript compiles.
- `npm run test` - Run policy/config/state tests.
- `npm run check:pack` - Verify package contents are safe.
- `npm run validate` - Run the full repository validation script.
- `pi --no-extensions -e .` - Manual isolated Pi smoke test with only GuardMe loaded.

## Notes

- Runtime dependencies likely needed during implementation: `yaml` for YAML parsing and a glob matcher such as `minimatch`.
- If string enum tool schemas are added later, use `StringEnum` from `@earendil-works/pi-ai` rather than `Type.Union` literals.
- Keep package metadata aligned with Pi package docs: Pi core packages in `peerDependencies` with `"*"`, non-Pi runtime libraries in `dependencies`, and development tools in `devDependencies`.
