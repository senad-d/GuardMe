# GuardMe repository investigation summary

Date: 2026-06-24

## Executive summary

This repository is a TypeScript Pi extension named `@senad-d/guardme`. GuardMe enforces IAM-like, deny-first guardrails around Pi LLM tool calls to shell and filesystem tools. The implementation is broad and security-focused: it loads global/project YAML policy, evaluates guarded tool calls before execution, persists warned-once JSONL state, provides approval/configuration TUI flows, and includes extensive unit/integration/e2e coverage.

Current validation status from this investigation:

- `npm run typecheck` passed.
- `npm test` ran 196 tests: 195 passed, 1 failed.
- The failing test shows drift between `scripts/install-global-policy.mjs` and `src/config/schema.ts#createBuiltInDefaultPolicy()`.
- `npm run check:pack` and `git status --short` were blocked by active GuardMe policy because those command segments are not currently allowlisted.

## Repository identity

- Package: `@senad-d/guardme`
- Version: `0.1.0`
- Runtime: ESM TypeScript, Node `>=22.19.0`
- Pi extension entrypoint: `src/extension.ts`
- Pi package metadata: `package.json` uses `pi.extensions: ["./src/extension.ts"]`
- Runtime dependencies: no non-Pi runtime dependencies are imported; Pi is a peer dependency.
- Main docs: `README.md`, `docs/POLICY.md`, `docs/VALIDATION.md`, `SECURITY.md`, `docs/PROJECT_DEFINITION_BRIEF.md`

## Architecture found

`src/extension.ts` is intentionally small and only wires registration modules:

- `src/events/register-lifecycle.ts`: loads settings, merged policy, warning state, and status on session start; clears state on shutdown.
- `src/events/register-guard.ts`: intercepts `tool_call` events for guarded built-in tools and maps them to policy requests.
- `src/events/register-guidance.ts`: injects model-facing `WARNINGS & DECISIONS` guidance after blocks.
- `src/commands/guardme-command.ts`: implements `/guardme`, `/guardme help`, setup flows, status, diagnostics, policy paths, project trust, and runtime active/off toggles.

Core modules are separated well:

- `src/config/*`: policy schema, custom YAML parser, global/local load/merge, runtime settings, policy writes.
- `src/policy/*`: domain types, path normalization/glob matching, command classification, script-content extraction, deny-first evaluator, redaction.
- `src/state/warnings.ts`: JSONL warning/decision state with redaction and symlink/size safeguards.
- `src/ui/*`: framed TUI/config panes, approval modal, setup wizard, diagnostic/warning formatting.

## Guarded behavior

GuardMe guards Pi tool calls for:

- `bash`
- `read`
- `write`
- `edit`
- `grep`
- `find`
- `ls`

Key enforcement behavior:

- Deny/protection rules win over allow rules.
- Inside-project read/list/write/edit is allowed by default unless a protection matches.
- Inside-project delete/move/rename requires approval unless explicitly allowed.
- Outside-project access requires explicit path policy.
- Shell commands are evaluated by executable segment and are default-deny unless each segment is allowed or approved.
- Dangerous and policy-missing actions use warned-once behavior: first block/coaching, repeated attempt asks the user when UI exists; no UI fails closed.
- `write`/`edit` inspect command-bearing proposed content before mutation.
- Local scripts and package-manager scripts are inspected before execution when detectable.

Hard protections include cloud CLIs, credential-like paths, `.env`, SSH/cloud credential locations, `.git` destructive operations, disk formatting/raw disk operations, unsafe privilege escalation, broad protected discovery, and symlink/oversized config-state safeguards.

## Config, policy, state, and settings

Policy files:

- Global: `~/.pi/agent/guardme.yaml`
- Project local: `.pi/agent/guardme.yaml`

Generated warning/decision state:

- Global: `~/.pi/agent/guardme-state.jsonl`
- Project local: `.pi/agent/guardme-state.jsonl`

Runtime settings:

- Project local: `.pi/agent/guardme-settings.json`

Trust behavior:

- Project-local policy, settings, and state are loaded only when the project is trusted.
- Untrusted-project warning state is recorded globally for the active cwd.
- Missing settings mean GuardMe is active.
- Invalid settings fail safe to active.

Persistence behavior:

- Policy writes use owner-only permissions and reject symlinked/out-of-scope targets.
- Saved decisions append narrow YAML rules and reload policy into the current session.
- GuardMe refuses to persist command rules containing secret-like values.

## Test and validation findings

Commands run:

```bash
npm run typecheck
npm test
npm run check:pack
```

Results:

- `npm run typecheck`: passed.
- `npm test`: failed 1 of 196 tests.
- `npm run check:pack`: blocked by GuardMe before execution because `npm run check:pack` has no matching `allowCommands` rule.

Failing test:

- File: `test/install-global-policy.test.mjs`
- Test: `postinstall creates global guardme.yaml with sensible defaults`
- Cause: installer-generated YAML contains extra `allowCommands` not present in `createBuiltInDefaultPolicy()`:
  - `npm run format*`
  - `node *`
  - `git *`

This is important because the test expects the postinstall global policy to equal the built-in default policy exactly. It also matters from a security-policy perspective: broad `node *` and `git *` installer defaults may be wider than the source built-in defaults and the documented conservative/default-deny model.

## Notable issues or drift

1. **Installer default policy drift**
   - `scripts/install-global-policy.mjs` and `src/config/schema.ts#createBuiltInDefaultPolicy()` disagree.
   - This currently breaks `npm test`.
   - Recommended next step: decide whether the extra installer allow rules are intentional. If not, remove them from the installer. If yes, update built-in defaults, docs, and tests deliberately.

2. **Validation command friction under GuardMe**
   - `docs/VALIDATION.md` recommends `npm run check:pack`, but active GuardMe blocked that exact command in this session.
   - Recommended next step: either add a narrow default allow for the documented check command or adjust docs to prefer `npm run validate` when GuardMe is active.

3. **Stale contributing wording**
   - `CONTRIBUTING.md` still says the project has “implementation pending,” while README/docs/source show implementation is complete and tested.
   - Recommended next step: update `CONTRIBUTING.md` to reflect current implementation status.

4. **Generated/report artifacts present in checkout**
   - `trivy-reports/` exists in the working tree and is ignored/forbidden from package contents by `.gitignore` and `scripts/check-package-contents.mjs`.
   - I could not confirm git tracking status because `git status --short` was blocked by GuardMe.

5. **Custom lightweight parsers are central security code**
   - The repo intentionally avoids runtime dependencies and implements lightweight YAML, glob, shell-tokenization, and script-content inspection logic in-repo.
   - This keeps packaging small but makes parser/classifier tests especially important. Existing tests are extensive and should remain mandatory for changes.

## Useful entry points for future work

- Extension wiring: `src/extension.ts`
- Tool-call enforcement: `src/events/register-guard.ts`
- Policy decision engine: `src/policy/evaluate.ts`
- Command classifier: `src/policy/commands.ts`
- Policy schema/defaults: `src/config/schema.ts`
- Installer default policy: `scripts/install-global-policy.mjs`
- Runtime settings: `src/config/runtime-settings.ts`
- Warning/decision state: `src/state/warnings.ts`
- `/guardme` command: `src/commands/guardme-command.ts`
- Config/approval TUI: `src/ui/config-tui.ts`, `src/ui/approval-modal.ts`
- Main policy reference: `docs/POLICY.md`
- Validation guide: `docs/VALIDATION.md`

## Overall assessment

GuardMe appears to be a mature, security-sensitive Pi extension with strong module boundaries and broad tests. The main immediate problem is default-policy drift between the installer and source defaults, causing the unit suite to fail. After reconciling that drift and updating stale docs, the repo should be in good shape for continued hardening and packaging validation.
