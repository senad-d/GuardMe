# GuardMe Policy Reference

GuardMe enforces IAM-like, deny-first policy for Pi LLM tool calls routed through this extension. It is not an OS sandbox and does not protect direct terminal commands, other processes, or user-entered `!` / `!!` shell escapes.

## Policy, state, and settings files

| Scope | Policy YAML | Generated JSONL state | Runtime settings |
| --- | --- | --- | --- |
| Global | `~/.pi/agent/guardme.yaml` | `~/.pi/agent/guardme-state.jsonl` | n/a |
| Project local | `.pi/agent/guardme.yaml` | `.pi/agent/guardme-state.jsonl` | `.pi/agent/guardme-settings.json` |

Global policy loads first. Project-local policy, runtime settings, and generated state are loaded only when the project is trusted. GuardMe runtime settings are project-local; missing settings mean GuardMe is active with Insecure edits off. `{ "version": 1, "enabled": false }` means GuardMe is off for that project after trust, and `{ "version": 1, "enabled": true, "insecureEdits": true }` means `write`/`edit` skip proposed content/script scanning while path protections and other guarded tools remain enforced. Invalid settings fail safe to active with Insecure edits off and report diagnostics. Missing policy files are accepted at runtime, and GuardMe still applies built-in defaults. Use `/guardme` Setup to create or update `~/.pi/agent/guardme.yaml` or `.pi/agent/guardme.yaml`; policy writes are explicit user actions, refuse symlinked policy paths, and use owner-only permissions for new files. Policy, runtime settings, and state reads fail closed for symlinked GuardMe paths or oversized files. In untrusted projects, new warned-once state is recorded in the global state file for the active cwd rather than trusting project-local state, and saved project settings apply after project trust is enabled.

## Built-in defaults and starter policies

The built-in defaults and policies created by Setup's sensible-defaults option include non-empty rules for:

- `allowPaths`: read/list access for Pi skill directories (`**/.pi/skills`, `**/.pi/skills/**`, and legacy `**/.pi/skill`, `**/.pi/skill/**`) plus local Homebrew Pi package documentation under `/opt/homebrew/lib/node_modules/@earendil-works`, so `SKILL.md` files and Pi docs can be loaded from outside the current repository. The exact `/dev/null` output sink is also approved for writes so otherwise allowed commands can suppress stdout or stderr.
- `zeroAccessPaths`: SSH, GPG, and password-manager local data.
- `noDeletePaths`: the `.git` directory, `.git/**` contents, and common package lockfiles.
- `denyPaths`: `.env`, `.npmrc`, `.pypirc`, `.netrc`, and similar token-bearing files. `.env.*` files are read/write/edit allowed by default so templates like `.env.example` can be maintained, but delete/move/rename is still denied by the starter policy, including broad destructive commands aimed at a parent directory containing direct `.env.*` descendants.
- `readOnlyPaths`: GuardMe policy and runtime-settings files, so LLM tool calls cannot rewrite policy or toggle GuardMe directly.
- `denyCommands`: cloud CLIs, privilege escalation (`sudo`, `sudoedit`, `doas`), and unsafe permission changes.
- `dangerousCommands`: recursive deletion, forced git clean, `find -delete`, and `rsync --delete` patterns.
- `protectedCredentialPaths`: cloud, Docker, npm, netrc, credential, secret, and token-like paths.
- Built-in credential path classification also catches case variants and glob-like operands such as `Secret.TXT`, `.SSH`, `.SSH*`, or ambiguous `.env*` shell globs before default project allows apply. Exact template paths such as `.env.example` are not hard-blocked by the built-in classifier unless your policy denies them.
- `allowCommands`: balanced starter command families (`pwd *`, `ls *`, `cat *`, `head *`, `tail *`, `wc *`, `grep *`, `find *`, `rg *`) plus common local validation commands such as `npm test*`, `npm run validate*`, `npm run check*`, and `npm run format*`, along with `node *` and `git *`. These patterns are still constrained by deny/path/script protections.

Shell commands are evaluated by executable segment. A compound such as `pwd && ls -lh` may run only when every segment is allowed and no stronger rule matches. Segments that are not hard-denied, explicitly denied, dangerous, or explicitly allowed are treated as policy-missing and blocked by default. This includes browser/GUI launchers, network clients, local executables, and other generic `bash` commands such as `brave ...` or `open -a Brave ...`.

## YAML shape

```yaml
version: 1

allowPaths:
  - pattern: "src/**"
    actions: [read, list, write, edit]
    reason: "Project source"

denyPaths:
  - pattern: "**/.env"
    actions: [read, list, write, edit, delete, move, rename]
    reason: "Environment files may contain credentials"
  - pattern: "**/.env.*"
    actions: [delete, move, rename]
    reason: "Environment template files can be read or edited, but destructive changes require review"

zeroAccessPaths:
  - pattern: "~/.ssh/**"
    reason: "SSH files are never available"

readOnlyPaths:
  - pattern: "docs/**"
    reason: "Documentation is read-only"

noDeletePaths:
  - pattern: ".git"
    reason: "Repository metadata must not be deleted"
  - pattern: ".git/**"
    reason: "Repository metadata contents must not be deleted"

allowCommands:
  - pattern: "pwd *"
    reason: "Working-directory discovery"
  - pattern: "ls *"
    reason: "Project file listing after path protections pass"
  - pattern: "npm run test*"
    reason: "Project validation"

denyCommands:
  - pattern: "sudo *"
    reason: "Privilege escalation is blocked"
  - pattern: "sudoedit *"
    reason: "Privilege escalation is blocked"

dangerousCommands:
  - pattern: "rm -rf *"
    reason: "Recursive deletion requires approval"

protectedCredentialPaths:
  - pattern: "~/.aws/**"
    reason: "Cloud credentials are protected"
```

Supported path actions are `read`, `list`, `write`, `edit`, `delete`, `move`, and `rename`. Command rules match normalized executable shell segments with simple glob syntax where `*` and `?` can match path separators inside command arguments. A trailing argument wildcard ending in ` *` is optional, so `ls *` matches both `ls` and `ls -lh`, and basename candidates allow `ls *` to match `/bin/ls -lh` during policy evaluation. Redirection operators are syntax within an executable segment, not standalone commands, so a pattern such as `2>*` does not independently allow stderr redirection. GuardMe recognizes the exact `/dev/null` path as a built-in sink, so that redirection leaves the underlying command classification intact; redirects to regular files remain write operations. Command rules do not support `actions`; command rules that include `actions` are rejected instead of being applied with surprising scope. Deny and dangerous command rules are also checked against executable shell segments, absolute executable paths, and common wrapper/subcommand forms, so `sudo`, `sudoedit`, `chmod 777`, or `rm -rf` appended after another command is still governed by the matching rule. Unsupported policy `version` values are reported as errors and their rules are ignored. Rules with malformed, empty, or path-incompatible `actions` lists are reported and are not broadened into all-action allow rules.

## Sections

- `allowPaths`: permits matching path actions when no deny or hard protection matches.
- `denyPaths`: blocks matching path actions and wins over `allowPaths`.
- `zeroAccessPaths`: blocks all access, including reads, lists, writes, edits, deletes, moves, and renames.
- `readOnlyPaths`: allows read/list but blocks mutations.
- `noDeletePaths`: blocks delete, destructive move, and destructive rename, including broad destructive commands aimed at a directory containing protected descendants such as `.git`.
- `allowCommands`: permits matching executable shell segments only when no deny rule, hard-deny, protected path rule, outside-project path requirement, or script-content violation matches. Wildcard allow rules can approve non-dangerous safe command families such as `pwd *`, `ls *`, `cat *`, `grep *`, and `find *` after path gates pass. Exact allow command rules are required for dangerous, delete, move, and rename shell segments. A compound command is allowed only when every executable segment is allowed, or when a compatible exact whole-command rule matches after all deny/path gates pass.
- `denyCommands`: blocks matching shell commands and wins over `allowCommands`.
- `dangerousCommands`: blocks the first matching fingerprint with coaching; repeated fingerprints require user approval.
- `protectedCredentialPaths`: protects credential-like paths such as cloud config directories and secret files.

## Precedence

Deny always wins:

1. Built-in hard denials block first: cloud CLIs (`aws`, `az`, `gcloud`) even through common command wrappers, package runners such as `npx`, `npm exec`, `pnpm dlx`, `yarn dlx`, and `bunx`, `env -C`/`-S`/`--split-string`, shell `-c` option variants, ANSI-C quoted or line-continued command names, dynamic shell-expanded command names, shell substitutions, command separators, `find -exec` forms, shell control-flow/grouping forms, `eval`/`exec`, and inline interpreter calls; disk formatting/raw disk operations; `.git` deletion; and credential-like path access, including common read/copy/archive commands, metadata edits, ambiguous glob operands such as `.env*` that could include `.env`, broad `grep`/`ggrep`/`find` discovery over directories with direct protected descendants even when the discovery segment appears in a compound command, input-redirection forms such as `grep token < ~/.aws/credentials`, inline credential path literals, and `dd if/of` operands.
2. `zeroAccessPaths`, `readOnlyPaths`, `noDeletePaths`, and `protectedCredentialPaths` hard-block matching protected actions, including delete/move/rename requests aimed at a directory containing protected descendants discovered by GuardMe's bounded scan.
3. `denyPaths` and `denyCommands` block before allow rules.
4. Outside-project path access is denied unless an explicit `allowPaths` rule permits the action, or `readOnlyPaths` permits the read/list action. Command allow rules do not override this path requirement.
5. `allowPaths` and segment-aware `allowCommands` can allow only if no deny/protection/outside-project path requirement matched. Exact command allow rules can persist approval for dangerous-but-not-hard-forbidden inside-project shell commands. Wildcard command families such as `pwd *` and `ls *` can allow `pwd && ls -lh`, but a single unallowed or unsafe segment blocks the full command: `pwd && unknown-tool` is policy-missing, `pwd && ls -lh && rm -rf build` is dangerous, `cat .env` is protected, `cat /etc/passwd` is outside-project, and `find . -delete` requires exact approval. Broad wildcard allow rules such as `npm test*` cannot approve appended guarded segments like `npm test && rm -rf build` or wrapped denied commands.
6. Proposed `write`/`edit` payloads that look command-bearing are scanned before mutation unless Insecure edits is on. Shell scripts, Makefile recipes, `package.json` scripts, Dockerfile `RUN`, CI `run:` blocks (including YAML block scalar chomping/indent headers such as `|+`), and obvious shell heredocs are evaluated with the same command policy; denied, hard-denied, dangerous, policy-missing, or uninspectable command-bearing content blocks the mutation. When Insecure edits is on, GuardMe skips only this proposed content/script scan for `write`/`edit`; path protections, deny rules, outside-project write requirements, and other guarded tools still run.
7. Local script execution such as `./script.sh`, `script.sh`, `bash script.sh`, `sh script`, or `zsh script.zsh` is inspected before execution when the script can be read through policy. Unreadable, binary, too-large, outside-policy, or ambiguous local scripts fail closed.
8. Package-manager script execution such as `npm test`, `npm run test`, `pnpm run build`, `yarn test`, or `bun run test` inspects the relevant `package.json` script plus matching `pre*`/`post*` lifecycle scripts when `package.json` can be read through policy. Package-manager cwd/prefix options such as `npm --prefix packages/app test`, `npm test --prefix packages/app`, `pnpm -C packages/app run build`, `yarn --cwd packages/app test`, and `bun --cwd packages/app run test` point inspection at that package's `package.json` when they appear before the script argument separator `--`. Hard-denied, dangerous, protected-path, or outside-project findings block before execution; ordinary script runner commands inherit the allowed package command instead of being default-denied solely because they came from `package.json`.
9. Dangerous commands, policy-missing commands, script-content findings, and default inside-project delete/move/rename behavior use warned-once coaching, then user approval, when no exact allow matched.
10. Default project policy allows direct built-in tool read/list/write/edit inside `ctx.cwd`; outside-project access requires explicit allow/read-only rules. It does not implicitly allow generic `bash` commands.

Outside-project writes, edits, deletes, moves, and renames require explicit `allowPaths` and must not match any protection.

## Approval choices

For repeated dangerous-but-not-hard-forbidden actions or repeated policy-missing shell/script commands, GuardMe shows an approval flow when UI is available:

- Allow once
- Deny once
- Allow + save project rule
- Deny + save project rule
- Allow + save global rule
- Deny + save global rule

Escape/cancel behaves as deny once. In non-UI modes, approval-required actions fail closed.

Saved decisions append narrow YAML rules, reload policy for the current session, and record a decision in JSONL state. For policy-missing or dangerous compound commands, persistent allow decisions save the failed segment as an exact command rule by default rather than saving the whole compound. Warning records include reason codes such as `dangerous-command`, `policy-missing-command`, `script-content-denied`, and `local-script-uninspectable`; blocked deny decisions are also recorded with redacted reason and matched-rule metadata for the `/guardme` warning details screen. Model-facing follow-up guidance includes a `WARNINGS & DECISIONS` block with the reason and relevant matched rules. GuardMe refuses to save allow rules for hard-denied actions, refuses to persist command rules containing secret-like values, validates loaded JSONL state enums before using records, skips project-local policy/settings/state until the project is trusted, refuses symlinked or oversized policy/settings/state reads, refuses policy and runtime-settings writes that would follow symbolic links out of the expected config path, and refuses generated state writes through project-local state symlinks.

## `/guardme` General pane

`/guardme` opens on General. The first row toggles GuardMe between `active` and `off`; disabling requires confirmation and writes `.pi/agent/guardme-settings.json`, while enabling writes the same project-local setting without an extra confirmation. When GuardMe is off in a trusted project, guarded tool calls bypass GuardMe enforcement for that project. In an untrusted project, the setting is saved but ignored until project trust is enabled.

The second row toggles **Insecure edits**. Enabling requires confirmation because `write` and `edit` will skip proposed content/script scanning. This is useful for authoring scripts that contain commands GuardMe should still block at execution time, but path protections, deny rules, and credential paths still apply. `bash`, `read`, `grep`, `find`, and `ls` remain guarded, so running a generated local script is still inspected and can be blocked. Disabling Insecure edits restores normal write/edit content scanning without a confirmation.

The `Pi project trust` row writes Pi's saved project trust through Pi's trust store. This writes Pi’s project trust and may enable other project-local Pi resources after reload/restart. GuardMe reloads local policy, runtime settings, and state for the current session with the chosen trust value, but Pi project-local resources may require a restart or reload to fully reflect the new saved trust decision. `Warned fingerprints` and `Diagnostics` open human-readable detail screens; `Esc` returns to General.

## Examples

Global base policy:

```yaml
version: 1

denyCommands:
  - pattern: "sudo *"
    reason: "No privilege escalation"

zeroAccessPaths:
  - pattern: "~/.ssh/**"
    reason: "SSH material is unavailable"
```

Project-local overlay:

```yaml
version: 1

readOnlyPaths:
  - pattern: "docs/**"
    reason: "Read docs, do not edit them"

allowPaths:
  - pattern: "test/**"
    actions: [read, list, write, edit]
    reason: "Tests can be updated"
```

Segment-aware command examples:

```yaml
version: 1

allowCommands:
  - pattern: "pwd *" # matches pwd and pwd -L
  - pattern: "ls *"  # allows pwd && ls -lh only when pwd * is also allowed
  # cat * still cannot read .env or /etc/passwd without path permission.
  # .env.example is allowed unless your policy denies it.
  - pattern: "cat *"
  - pattern: "find *" # still cannot approve find . -delete
```

Saved approval example:

```yaml
version: 1

allowCommands:
  - pattern: "rm -rf build"
    reason: "Saved from GuardMe approval decision 'allow-local'."
```

## Limitations

GuardMe only evaluates tool calls seen by Pi extension hooks. It does not sandbox the OS, stop commands run in another terminal, or provide broad network/git policy. For stronger isolation, use a container, VM, or OS-level sandbox in addition to GuardMe.
