# Project Definition Brief

## 1. Bootstrap

- Template source: `/Users/senad/Documents/Code/Moj_git/pi-tmp`
- Target directory: `/Users/senad/Documents/Code/Moj_git/guardme`
- Copy status: copied into this repository; GuardMe feature implementation is complete for the approved task spec.

## 2. Project identity

- Package name: `@senad-d/guardme`
- Display name: `GuardMe`
- Exported extension function: `guardMe`
- Repository URL: `https://github.com/senad-d/GuardMe`
- One-sentence pitch: GuardMe is a Pi extension that enforces IAM-like allow/deny policy for LLM tool access to shell commands and local files during Pi sessions.

## 3. Users and use cases

- Primary users: Pi users who want local project boundary protection.
- Primary use cases:
  - Prevent LLMs from reading, writing, or deleting outside approved paths.
  - Enforce deny-first policy with `zeroAccessPaths`, `readOnlyPaths`, and `noDeletePaths`.
  - Coach the LLM on first dangerous attempts and ask the user on repeated dangerous attempts.
  - Persist policy in YAML and warning state in JSONL.
- Non-goals:
  - OS-level sandboxing.
  - Guarding commands outside Pi.
  - Git/network policy except always-denying cloud CLIs and credential access.

## 4. Pi integration surface

| Surface | Name | Purpose | Notes |
| --- | --- | --- | --- |
| Command | `/guardme` | Status/setup/policy help command | Implemented |
| Tool | none | No new LLM tool | GuardMe intercepts built-in tools instead |
| Event | `tool_call` | Enforcement before `bash`, `read`, `write`, `edit`, `grep`, `find`, and `ls` execute | Deny wins |
| Event | `before_agent_start` | Coaching/system guidance injection after blocked or policy-missing events | Injects concise follow-up guidance without file contents or command output |
| Event | `session_start` / `session_shutdown` | Config/state load and cleanup | No long-lived resources in factory |
| UI | custom approval modal | TUI/select allow/deny choices | Shows risk, matched rules, action/path/command |
| Resource | none | No skills/prompts/themes | Keep package focused |

## 5. Architecture

- Implemented files:
  - `src/extension.ts` small entry point.
  - `src/config/*` for YAML load/merge/validation.
  - `src/state/*` for JSONL warned-once state.
  - `src/policy/*` for action classification, glob matching, precedence.
  - `src/events/*` for Pi event registration.
  - `src/ui/*` for approval modal.
  - `src/commands/*` for `/guardme`.
- Module boundaries:
  - Config/state/policy pure modules testable without Pi.
  - Pi event handlers adapt tool calls into policy decisions.
  - UI only handles user decision capture.
- Dependencies:
  - No non-Pi runtime dependencies are currently imported; lightweight YAML/glob/script-content helpers are implemented in-repo.
  - Pi core packages stay in `peerDependencies` with `"*"`.

## 6. Config, state, and persistence

- Config source:
  - Global base: `~/.pi/agent/guardme.yaml`
  - Local overlay: `.pi/agent/guardme.yaml`
  - Arrays merged/unioned; local can tighten but never weaken global hard protections/denies.
- Session state:
  - Warned-once fingerprints persisted in separate JSONL state.
- Files written:
  - Global policy YAML is created during package postinstall if missing and populated with sensible defaults.
  - Project-local policy YAML is created when the user saves a rule or runs setup.
  - State JSONL when GuardMe records first warnings.
- Cleanup behavior:
  - No background processes, watchers, timers, or sockets.

## 7. Security and privacy

- Shell execution: LLM `bash` tool calls are inspected; cloud CLIs and destructive commands are denied or gated per policy.
- File access/mutation: reads, writes/edits, deletes/renames/moves, and discovery tools are guarded as read/list actions.
- Network access: not managed except cloud CLI commands are always denied.
- Credentials/secrets:
  - Reading credentials outside the project is strictly forbidden.
  - `.env`, SSH keys, cloud credential dirs/files, and credential-like files are protected by built-in defaults.
- Telemetry/retention: no telemetry planned.
- User confirmations:
  - TUI choices: allow once, deny once, allow/deny saved to local, allow/deny saved to global.
  - No UI/non-interactive prompt-needed action defaults to block.

## 8. Documentation and packaging

- README changes: describe implemented GuardMe behavior and link policy/validation docs.
- SECURITY changes: document Pi-session enforcement, not OS sandboxing.
- CHANGELOG changes: track implementation milestones.
- package.json changes:
  - rename package to `@senad-d/guardme`
  - update description, repo URLs, keywords
  - remove template metadata block
- npm/git distribution plan: npm package plus GitHub repo.

## 9. Validation plan

- Typecheck: `npm run typecheck`
- Tests: comprehensive unit/integration coverage for implemented policy behavior.
- Package dry-run: `npm run check:pack`
- Isolated Pi smoke test: `pi --no-extensions -e .`

## 10. Open questions and assumptions

- Questions:
  - None blocking implementation.
- Assumptions:
  - Strictly forbidden classes block immediately.
  - “Coach first, ask on repeat” applies to dangerous-but-not-hard-forbidden actions.
  - GuardMe only protects LLM tool calls inside Pi sessions.
- Decisions:
  - Deny always wins.
  - Hard path rules always win.
  - Cloud CLIs are always denied.
  - Global config is base; local config overlays/adds stricter project rules.
  - Warning memory is separate JSONL state.
  - `grep`, `find`, and `ls` are read/list/discovery actions and must be guarded.
  - User-entered `!`/`!!` shell escapes are out of scope for the initial implementation.
  - Package installation creates the global YAML if missing; if config files are later removed, GuardMe still runs with built-in defaults.
