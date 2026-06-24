# GuardMe

GuardMe is a Pi extension for IAM-like allow/deny guardrails around LLM tool access to shell commands and local files inside Pi sessions.

> **Implementation status:** GuardMe implements policy loading/merging, deny-first tool-call enforcement, warned-once state, approval UI, YAML rule persistence, installer-created global defaults, and the `/guardme` configuration TUI. The approved design and implementation plan live in `docs/PROJECT_DEFINITION_BRIEF.md` and `specs/`.

## Behavior

GuardMe protects Pi LLM tool calls by checking them before execution:

- shell commands through the Pi `bash` tool
- file reads through `read`
- file discovery/listing through `grep`, `find`, and `ls`
- file writes/edits through `write` and `edit`, including command-bearing script/content inspection before mutation
- local script execution such as `./script.sh` or `bash script.sh`, plus package-manager script execution such as `npm test`/`npm run test` (including package-manager cwd/prefix options before or after the script name, until `--`), with script content inspected before execution
- deletes, renames, and moves detected from shell commands

Policy is deny-first, similar to AWS IAM: deny rules and hard protections always win over allow rules. Shell commands are segment-aware and default-deny: every executable segment in a `bash` command must match `allowCommands` or go through the warned-once/user-approval flow. Patterns such as `pwd *` and `ls *` can allow `pwd && ls -lh`, while `pwd && unknown-tool`, `cat .env`, `cat /etc/passwd`, and `find . -delete` still block. See `docs/POLICY.md` for the full YAML reference.

## Policy files

GuardMe uses YAML policy files:

| Scope | Path | Role |
| --- | --- | --- |
| Global | `~/.pi/agent/guardme.yaml` | Base policy shared across projects |
| Project local | `.pi/agent/guardme.yaml` | Project-specific overlay/additions |

YAML sections:

- `allowPaths`
- `denyPaths`
- `zeroAccessPaths`
- `readOnlyPaths`
- `noDeletePaths`
- `allowCommands`
- `denyCommands`
- `dangerousCommands`
- `protectedCredentialPaths`

Generated warned-once state is kept separate from policy:

| Scope | Path |
| --- | --- |
| Global | `~/.pi/agent/guardme-state.jsonl` |
| Project local | `.pi/agent/guardme-state.jsonl` |

Project-local runtime settings are kept in `.pi/agent/guardme-settings.json`. Missing settings mean GuardMe is active. Setting GuardMe `off` from `/guardme` writes this file for the current project and bypasses GuardMe enforcement until it is turned active again, but project-local settings are honored only after the project is trusted.

On installation, GuardMe creates `~/.pi/agent/guardme.yaml` with sensible defaults if it does not already exist. If that file is removed, GuardMe still runs with built-in defaults. Project-local YAML, runtime settings, and generated state are loaded only when the project is trusted. Policy/settings/state reads fail closed for symlinked GuardMe paths or oversized files, and new policy writes use owner-only file permissions. In untrusted projects, new warning state is recorded globally for the active cwd instead of writing project-local state, and saved project settings apply after project trust is enabled. Project-local YAML is created from the Setup pane in `/guardme` or by saving an approval decision, and saved decisions are reloaded for the current session after they are written. GuardMe refuses to persist command rules that contain secret-like values; use allow once or add a sanitized rule manually.

## Hard protections

These protections are non-overridable:

- deny always wins over allow
- `zeroAccessPaths` are never readable or writable
- `readOnlyPaths` cannot be mutated
- `noDeletePaths`, including the `.git` directory itself and its contents, cannot be deleted, moved destructively, renamed destructively, or removed through broad parent-directory destructive commands
- cloud CLIs (`aws`, `az`, `gcloud`) are always denied by GuardMe, including common wrappers, package runners such as `npx`/`npm exec`/`pnpm dlx`/`yarn dlx`/`bunx`, `env -C`/`-S`/`--split-string`, shell `-c` option variants, shell substitutions, ANSI-C quoted or line-continued command names, dynamic shell-expanded command names, inline interpreter calls, command separators, `find -exec`, and control-flow/grouping forms
- default deny command rules catch privilege-escalation and unsafe-permission forms such as `sudo`, `sudoedit`, `doas`, and `chmod 777`, including absolute executable paths
- credential-like shell operands and inline credential path literals are detected across common read, copy, archive, metadata-edit, redirection, interpreter, and `dd if/of` forms before execution
- deleting `.git` is denied
- disk formatting/raw disk operations are denied
- credential-like paths are protected case-insensitively before default project allows apply
- command allow rules are evaluated per executable shell segment and cannot approve outside-project path access unless a matching path rule permits the classified action; wildcard command allows such as `pwd *`, `ls *`, or `npm test*` also cannot approve appended guarded shell segments, wrapped deny commands, dangerous/delete/move/rename segments without exact approval, or local script content that fails policy
- `.env`, SSH keys, cloud credential directories, and credential-like files are protected by default; `.env.example`-style templates are read/write/edit allowed unless your policy denies them, while ambiguous shell globs such as `cat .env*` still block because they could include `.env`

## User approval flow

For dangerous-but-not-hard-forbidden actions and policy-missing shell/script commands:

1. First matching attempt: block the tool call, give the LLM safer-behavior coaching, and record a JSONL warning fingerprint with a reason code.
2. Repeated matching attempt: ask the user in an in-session framed TUI approval prompt when UI is available.
3. No UI available: block the action.

When GuardMe injects model-facing follow-up guidance, it includes a `WARNINGS & DECISIONS` block with the block reason and relevant matched rule details.

Approval choices:

- Allow once
- Deny once
- Allow + save project rule
- Deny + save project rule
- Allow + save global rule
- Deny + save global rule

## Commands

- `/guardme` opens the framed GuardMe configuration TUI on the General pane, followed by Policies, Rules, and Setup.
- `/guardme help` shows compact command usage.

The General pane can turn GuardMe `active`/`off` per project, update Pi's saved project trust with a restart/reload note, and open human-readable warning/decision and diagnostic detail screens. The Setup pane requires confirmation before writing global or project policy files.

## Scope and limitations

GuardMe is Pi-session enforcement only. It is not an OS sandbox and cannot protect against commands run outside Pi or by other processes. For stronger isolation, run Pi in a container, VM, or OS-level sandbox.

Initial implementation scope excludes general git and network policy. Cloud CLIs are denied because they commonly expose credentials or remote mutation. Broader network and git guardrails may be handled by separate extensions later.

## Installation

Not published yet. After release, the package name is:

```bash
pi install npm:@senad-d/guardme
```

For local development and isolated smoke testing from this checkout:

```bash
npm install
npm run validate
pi --no-extensions -e .
```

`npm install` runs GuardMe's postinstall script, which creates the global policy if missing. For local development where you do not want that side effect, run `GUARDME_SKIP_GLOBAL_POLICY_INSTALL=1 npm install`.

## Development

This repository contains the GuardMe implementation, policy docs, validation docs, and tests. Start with:

```bash
npm install
npm run validate
```

Useful checks:

```bash
npm run typecheck
npm run test
npm run check:pack
pi --no-extensions -e .
```

Implementation must follow:

- `docs/PROJECT_DEFINITION_BRIEF.md`
- `docs/POLICY.md`
- `docs/VALIDATION.md`
- `specs/spec-architecture.md`
- `specs/spec-guidelines.md`
- `specs/spec-tasks.md`

## Security

Read `SECURITY.md` before installing or developing GuardMe. Pi extensions run with the local user's permissions. GuardMe is intended to reduce accidental or model-requested access inside Pi sessions, not to create a privilege boundary.

## License

MIT
