# GuardMe Policy Reference

GuardMe enforces IAM-like, deny-first policy for Pi LLM tool calls routed through this extension. It is not an OS sandbox and does not protect direct terminal commands, other processes, or user-entered `!` / `!!` shell escapes.

## Policy, state, and settings files

| Scope | Policy YAML | Generated JSONL state | Runtime settings |
| --- | --- | --- | --- |
| Global | `~/.pi/agent/guardme.yaml` | `~/.pi/agent/guardme-state.jsonl` | n/a |
| Project local | `.pi/agent/guardme.yaml` | `.pi/agent/guardme-state.jsonl` | `.pi/agent/guardme-settings.json` |

Global policy loads first. Project-local policy, runtime settings, and generated state are loaded only when the project is trusted. GuardMe runtime settings are project-local; missing settings mean GuardMe is active with Insecure edits off. `{ "version": 1, "enabled": false }` means GuardMe is off for that project after trust, and `{ "version": 1, "enabled": true, "insecureEdits": true }` means `write`/`edit` skip proposed content/script scanning while path protections and other guarded tools remain enforced. Invalid settings fail safe to active with Insecure edits off and report diagnostics. Missing policy files are accepted at runtime, and GuardMe still applies built-in defaults. Use `/guardme` Setup to create or update `~/.pi/agent/guardme.yaml` or `.pi/agent/guardme.yaml`; policy writes are explicit user actions, refuse symlinked policy paths, and use owner-only permissions for new files. Policy, runtime settings, and state reads fail closed for symlinked GuardMe paths or oversized files. In untrusted projects, new warned-once state is recorded in the global state file for the active cwd rather than trusting project-local state, and saved project settings apply after project trust is enabled.

Approval behavior is configured by the top-level policy key `approvalMode` (`auto`, `interactive`, `agent`, or `block`). Built-in `auto` is the safe default. Global policy can set the mode, trusted project policy overrides global policy, and `GUARDME_APPROVAL_MODE` overrides both for the current process. Invalid policy or environment values produce error diagnostics and resolve to `block` for the invalid source/override; an untrusted project's mode is not loaded.

## Built-in defaults and starter policies

The built-in defaults and policies created by Setup's sensible-defaults option include non-empty rules for:

- `allowPaths`: read/list access for Pi skill directories (`**/.pi/skills`, `**/.pi/skills/**`, and legacy `**/.pi/skill`, `**/.pi/skill/**`) plus all package contents under `**/node_modules/@earendil-works/**` (and discovery of the scope directory itself) across sibling-project, global npm, and Homebrew installations; this covers every package in the scope, not just `pi-coding-agent`, without granting mutations or overriding deny/protection rules, so `SKILL.md` files and Pi docs can be loaded from outside the current repository. The exact `/dev/null` output sink is also approved for writes so otherwise allowed commands can suppress stdout or stderr.
- `zeroAccessPaths`: SSH, GPG, password-manager local data, and Pi's own credentials (`~/.pi/agent/auth.json`).
- `noDeletePaths`: the `.git` directory, `.git/**` contents, and common package lockfiles.
- `denyPaths`: `.env`, `.npmrc`, `.pypirc`, `.netrc`, and similar token-bearing files. All `.env.*` files are protected from delete/move/rename by the starter policy, including broad destructive commands aimed at a parent directory containing direct `.env.*` descendants. Non-template variants such as `.env.local` and `.env.production` are additionally read/write protected by the built-in credential classifier; template names (`.env.example`, `.env.sample`, `.env.template`, `.env.dist`) stay readable and editable.
- `readOnlyPaths`: GuardMe policy and runtime-settings files, so LLM tool calls cannot rewrite policy or toggle GuardMe directly. Outside the project, only readOnlyPaths rules anchored to an absolute or `~/` location grant reads; relative and `**/`-prefixed globs protect against writes without opening reads across the disk.
- `denyCommands`: cloud CLIs, privilege escalation (`sudo`, `sudoedit`, `doas`), unsafe permission changes, environment dumps (`env` with no wrapped command, `printenv`), and credential-printing subcommands (`gh auth token`, `git credential`, npm authToken lookups).
- Unattended mutations: `rm`, `rmdir` and `mv` (including recursive `rm`) of concrete paths are allowed by the default `rm *`, `rmdir *` and `mv *` rules once the path protections pass, when every target is inside the project or under an `allowPaths` rule granting the action (the temp directories by default), so agents can remove or rename their own files. The project root, globs, shell variables, `~`, other outside paths, and every other delete-capable command (`find -delete`, `rsync --delete`, `git clean -f`) still require an exact allow rule or user approval.
- Temp directories: `/tmp`, `/var/tmp` and the macOS per-user temp directory (`/var/folders/*/*/T`) are allowed for read, list, write, edit, delete, move and rename, so scratch files, logs and downloads do not interrupt an agent. Credential-like names and `.env` files stay protected inside them. A project checked out under the temp directory is covered by the same allowance, which weakens the discovery gates there.
- Shell syntax and builtins: the command after `if`, `while`, `until`, `elif` or `!` is what the rules see; `for`, `select` and `case` headers execute nothing and match like the no-op. `cd` is a list action whose operand goes through the path checks, so `cd` into or out of the project is governed like `ls`. `export`, `unset`, `wait`, `exit`, `return`, `type`, `read`, `jobs`, `disown`, `shift`, `local`, `umask`, `hash`, `false` and `:` are allowed; exporting `PATH`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_INSERT_LIBRARIES`, `DYLD_LIBRARY_PATH`, `NODE_OPTIONS` or `BASH_ENV` is denied because it redirects which programs later segments run.
- Toolchains and dev tools: JVM (`java`, `mvn`, `gradle` and their wrappers), .NET, PHP, Ruby, Rust and Python linters, JavaScript test runners and the dev servers and bundlers `npx` launches (`vite`, `serve`, `next`, `playwright`, `webpack` and others) are allowed; `npx` itself is allowed but the tool it launches is checked as its own segment.
- `dangerousCommands`: forced git clean, `find -delete`, and `rsync --delete` patterns (recursive `rm` outside the project, on globs or on the project root is classified dangerous without a rule), plus file-writing side channels that skip content scanning (`git apply`, `git … core.hooksPath`, `npm pkg set`, `npm set-script`).
- `protectedCredentialPaths`: cloud, Docker, npm, and netrc credential paths. Keyword-named files (`secrets.yaml`, `my-token.txt`, `credentials.json`) are hard-denied by the built-in credential path classifier, which matches keywords on word boundaries so code files such as `tokenizer.ts` or `secretary.md` are not blocked.
- Built-in credential path classification also catches case variants and glob-like operands such as `Secret.TXT`, `.SSH`, `.SSH*`, or ambiguous `.env*` shell globs before default project allows apply, plus non-template `.env.*` variants such as `.env.local`. Exact template paths such as `.env.example` are not hard-blocked by the built-in classifier unless your policy denies them. Environment reads in inline interpreter code (`process.env`, `os.environ`, `import.meta.env`) are also hard-denied.
- `allowCommands`: balanced starter command families (`pwd *`, `ls *`, `cat *`, `head *`, `tail *`, `wc *`, `grep *`, `find *`, `rg *`), text/file utilities (`awk *`, `sed *`, `cut *`, `sort *`, `diff *`, `tee *`, `tar *`, and similar), package managers and runners (`npm *`, `npx *`, `pnpm *`, `yarn *`, `bun *`), language toolchains (`node *`, `python3 *`, `pip *`, `cargo *`, `go *`, `tsc *`, `eslint *`, `vitest *`), and `git *`. These patterns are still constrained by deny/path/script protections, and wrapped commands (`xargs *`, `timeout *`, package runners) still have their inner commands checked segment by segment.

Shell commands are evaluated by executable segment. A compound such as `pwd && ls -lh` may run only when every segment is allowed and no stronger rule matches. `find -H`, `find -L`, and `find -P` preserve explicit starting paths. Because `find -L` follows symbolic links and descendant links can escape an otherwise reviewed root, it conservatively requires an exact `allowCommands` rule or user approval. Its diagnostic names symlink traversal rather than claiming an unrelated project `.env` was accessed. Segments that are not hard-denied, explicitly denied, dangerous, or explicitly allowed are treated as policy-missing and blocked by default. This includes browser/GUI launchers, network clients without a default allow (unlike `curl`), local executables, and other generic `bash` commands such as `brave ...` or `open -a Brave ...`.

### Checksums, curl, and heredocs

- `shasum *` is allowed by default for direct file checksums, including `shasum -a 256 file ...` in a Git inspection compound. Algorithm values are not treated as paths. Credential and outside-project file protections still apply. Manifest checks (`-c`/`--check`) require exact approval because a manifest can name additional files.
- `curl *` is an ordinary default-allowed command. GuardMe adds no domain, protocol or network-traffic allowlist and does not require `-q`; network filtering can be owned by another extension. Explicit local file arguments are checked: output, upload, data/JSON `@file`, multipart files, header files, cookies, TLS files, traces, and local `file:` URLs. Separate, attached short, and `--option=value` forms are recognized. `--output-dir` is combined with explicit output filenames; `/dev/null` remains an approved output sink.
- Curl config files (`-K`/`--config`), remote-derived output names (`-O`/`-J`), expanded options, multiple transfer groups and unresolved file operands require exact approval. Static inspection covers recognized explicit file arguments, not all curl behavior: implicit `.curlrc` settings and future/unrecognized options are not inspected. Mixed read/write commands conservatively apply the write action to all extracted paths. This is not a filesystem sandbox.
- Supported quoted stdin heredocs are parsed as a unit. Node/Python/Ruby/Perl/PHP bodies receive the existing inline-code checks, shell interpreter bodies receive shell-command checks, and literal `cat`/`wc` stdin stays data. JavaScript imports, arrays and backticks do not become shell commands. The transformation is analysis-only; tool input is never rewritten. Multiple documents, quoted/escaped delimiters and `<<-` tab stripping preserve body boundaries and trailing commands.
- Unquoted, malformed, unsupported-consumer or ambiguously routed heredocs (including pipelines and non-stdin descriptors) fail closed with a heredoc-specific diagnostic. Quoting a delimiter does not disable interpreter credential/environment/cloud guards or authorize shell commands in its body. Local/proposed scripts retain their existing exact-command approval requirement, with full heredoc units retained for inspection.

## YAML shape

`guardedTools` maps a third-party tool name to one of GuardMe's built-in input contracts. A `bash` contract is shell-classified; the other contracts reuse that path tool's target extraction, action, discovery, and content checks.

```yaml
version: 1
approvalMode: auto

guardedTools:
  pwsh: bash
  file_viewer: read

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
    reason: "Env file variants must not be deleted, moved, or renamed; non-template variants are also read/write protected by the built-in credential classifier"

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

The built-in mappings `bash`, `read`, `write`, `edit`, `grep`, `find`, and `ls` always map to themselves and cannot be remapped. Global aliases load first, then aliases from a trusted project policy are added. Repeating the same alias-to-contract mapping is deduplicated; a conflicting later mapping reports an error and the earlier mapping remains effective. Project aliases are ignored when the project is untrusted. GuardMe does not infer third-party tool semantics: an unknown or unmapped tool remains outside enforcement. Use `/guardme diagnostics` or the Policies pane to inspect every effective mapping and distinguish built-ins from configured aliases.

Supported path actions are `read`, `list`, `write`, `edit`, `delete`, `move`, and `rename`. Command rules match normalized executable shell segments with simple glob syntax where `*` and `?` can match path separators inside command arguments. A trailing argument wildcard ending in ` *` is optional, so `ls *` matches both `ls` and `ls -lh`, and basename candidates allow `ls *` to match `/bin/ls -lh` during policy evaluation. Redirection operators are syntax within an executable segment, not standalone commands, so a pattern such as `2>*` does not independently allow stderr redirection. GuardMe recognizes the exact `/dev/null` path as a built-in sink, so that redirection leaves the underlying command classification intact; redirects to regular files remain write operations. Command rules do not support `actions`; command rules that include `actions` are rejected instead of being applied with surprising scope. Deny and dangerous command rules are also checked against executable shell segments, absolute executable paths, and common wrapper/subcommand forms, so `sudo`, `sudoedit`, `chmod 777`, or `rm -rf` appended after another command is still governed by the matching rule. `command`, `builtin`, `noglob`, `nohup` and `exec` are prefix wrappers: the wrapped command is what gets classified and matched. Unsupported policy `version` values are reported as errors and their rules are ignored. Rules with malformed, empty, or path-incompatible `actions` lists are reported and are not broadened into all-action allow rules.

### Approval modes

- `auto`: TUI sessions may show GuardMe's existing approval UI. RPC, JSON, print, and unknown/non-interactive modes block without invoking an approval dialog method.
- `interactive`: GuardMe may use the relevant approval method when Pi reports UI support. This is required for an RPC controller that intentionally handles `extension_ui_request` and sends `extension_ui_response`.
- `agent`: no session ever shows approval UI. Every run mode (TUI included) uses an in-memory turn gate: the first matching attempt in the current process and same-turn duplicates block with a short agent-facing notification; an identical fingerprint retried in a later agent turn receives one automatic allow-once. That approval saves no YAML rule and appends an `automatic-decision` audit record. Dangerous actions consume the approval immediately, so each repetition needs a new block/retry cycle; a policy-missing command stays allowed for the rest of the session after its first automatic approval, with every reuse audited.
- `block`: GuardMe never invokes `ui.custom`, `ui.select`, or another interactive approval method.

`agent` is an explicit opt-in for managed child processes, for example `GUARDME_APPROVAL_MODE=agent pi --mode json ...`. Pi exposes the current run mode but no reliable subagent marker, so GuardMe does not auto-detect children or enable this mode automatically. Set the override only for explicitly managed children. Persisted warned fingerprints do not arm the in-memory gate, so a new process still blocks its first attempt. Duplicate tool calls from one assistant response share the same turn and cannot become the required later retry. Automatic approval is available only for decisions that already passed hard-deny, explicit command/path deny, protected-path/credential, and outside-project checks. Use `auto` or `block` when automatic approval is not intended, and do not set `interactive` unless an RPC controller owns the complete approval response path.

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

1. Built-in hard denials block first: cloud CLIs (`aws`, `az`, `gcloud`) even through common command wrappers, package runners such as `npx`, `npm exec`, `pnpm dlx`, `yarn dlx`, and `bunx`, `env -C`/`-S`/`--split-string`, shell `-c` option variants, ANSI-C quoted or line-continued command names, dynamic shell-expanded command names, shell substitutions, command separators, `find -exec` forms, shell control-flow/grouping forms, `eval`/`exec`, and inline interpreter calls; environment dumps (`env` with no wrapped command, `printenv`, and inline interpreter reads of `process.env`/`os.environ`/`import.meta.env`); disk formatting/raw disk operations; `.git` deletion; and credential-like path access, including common read/copy/archive commands, metadata edits, non-template `.env.*` variants such as `.env.local`, ambiguous glob operands such as `.env*` that could include `.env`, input-redirection forms such as `grep token < ~/.aws/credentials`, inline credential path literals, and `dd if/of` operands. Broad content searches (`grep -r`, `rg`, `find`) are allowed after path protections pass; protected files such as `.env` stay unreadable directly, but their presence in a directory does not block searching it. Searches that hunt for credential-like file names (a `find -name` or grep glob containing `secret`, `token`, `credential`, or `.env` forms) are approval-gated: the first attempt is blocked with coaching and a repeat asks for user approval. A reviewed exact `allowCommands` rule for the whole command counts as sign-off.
2. `zeroAccessPaths`, `readOnlyPaths`, `noDeletePaths`, and `protectedCredentialPaths` hard-block matching protected actions, including delete/move/rename requests aimed at a directory containing protected descendants discovered by GuardMe's bounded scan.
3. `denyPaths` and `denyCommands` block before allow rules.
4. Outside-project path access is denied unless an explicit `allowPaths` rule permits the action, or `readOnlyPaths` permits the read/list action. Command allow rules do not override this path requirement.
5. `allowPaths` and segment-aware `allowCommands` can allow only if no deny/protection/outside-project path requirement matched. Exact command allow rules can persist approval for dangerous-but-not-hard-forbidden inside-project shell commands. Wildcard command families such as `pwd *` and `ls *` can allow `pwd && ls -lh`, but a single unallowed or unsafe segment blocks the full command: `pwd && unknown-tool` is policy-missing, `pwd && ls -lh && rm -rf build` is dangerous, `cat .env` is protected, `cat /etc/passwd` is outside-project, and `find . -delete` requires exact approval. Broad wildcard allow rules such as `npm test*` cannot approve appended guarded segments like `npm test && rm -rf build` or wrapped denied commands.
6. Proposed `write`/`edit` payloads that look command-bearing are scanned before mutation unless Insecure edits is on. Shell scripts, Makefile recipes, `package.json` scripts, Dockerfile `RUN`, CI `run:` blocks (including YAML block scalar chomping/indent headers such as `|+`), and obvious shell heredocs are evaluated with the same command policy; denied, hard-denied, dangerous, policy-missing, or uninspectable command-bearing content blocks the mutation. When Insecure edits is on, GuardMe skips only this proposed content/script scan for `write`/`edit`; path protections, deny rules, outside-project write requirements, and other guarded tools still run.
7. Local script execution such as `./script.sh`, `script.sh`, `bash script.sh`, `sh script`, or `zsh script.zsh` is inspected before execution when the script can be read through policy. Unreadable, binary, too-large, outside-policy, or ambiguous local scripts fail closed.
8. Package-manager script execution such as `npm test`, `npm run test`, `pnpm run build`, `yarn test`, or `bun run test` inspects the relevant `package.json` script plus matching `pre*`/`post*` lifecycle scripts when `package.json` can be read through policy. Package-manager cwd/prefix options such as `npm --prefix packages/app test`, `npm test --prefix packages/app`, `pnpm -C packages/app run build`, `yarn --cwd packages/app test`, and `bun --cwd packages/app run test` point inspection at that package's `package.json` when they appear before the script argument separator `--`. Hard-denied, dangerous, protected-path, or outside-project findings block before execution; ordinary script runner commands inherit the allowed package command instead of being default-denied solely because they came from `package.json`.
9. Dangerous commands, policy-missing commands, script-content findings, and default inside-project delete/move/rename behavior use warned-once coaching, then mode-specific approval when no exact allow matched. In explicit `agent` mode, only an identical later-turn retry in the same process can receive a consumed automatic allow-once.
10. Default project policy allows direct built-in tool read/list/write/edit inside `ctx.cwd`; outside-project access requires explicit allow/read-only rules. It does not implicitly allow generic `bash` commands.

Outside-project writes, edits, deletes, moves, and renames require explicit `allowPaths` and must not match any protection.

## Approval choices

For repeated dangerous-but-not-hard-forbidden actions or repeated policy-missing shell/script commands, GuardMe shows an approval flow only when the resolved approval mode permits it:

- Allow once
- Deny once
- Allow + save project rule
- Deny + save project rule
- Allow + save global rule
- Deny + save global rule

Escape or the configured selection-cancel binding behaves as deny once. The custom TUI follows Pi's configured selection bindings and uses a height-bounded compact layout in short panes; every decision remains reachable and the current decision, count, description, and safe cancellation guidance remain visible. Under `auto` outside TUI, under `block`, or whenever required UI support is absent, approval-required calls fail closed as ordinary blocked tool results. GuardMe does not synthesize a user decision, write an allow/deny rule, or append a decision record. The result includes bounded, redacted `WARNINGS & DECISIONS` guidance with risk, tool/action, target or command, reason, matched rules, explicit approval unavailability, safer alternatives, and a direction not to retry the identical request unchanged. Persisted warned fingerprints follow the same mode check and cannot force RPC UI under `auto`.

Under explicit `agent` mode, blocks instead explain that the identical request may be retried in a later agent turn. The gate is process-local and keyed by policy fingerprint plus GuardMe's monotonically tracked Pi turn. The automatic allow-once is consumed before another execution can use it, never writes policy, and is audited separately from `decision` records created by users. For dangerous actions, a call after consumption starts a new block/later-turn-retry cycle; approved policy-missing commands keep a session-scoped allowance instead, and each reuse appends its own audit record.

Saved interactive decisions append narrow YAML rules, reload policy for the current session, and record a decision in JSONL state. For policy-missing or dangerous compound commands, persistent allow decisions save the failed segment as an exact command rule by default rather than saving the whole compound. Warning records include reason codes such as `dangerous-command`, `policy-missing-command`, `script-content-denied`, and `local-script-uninspectable`; blocked deny decisions are also recorded with redacted reason and matched-rule metadata for the `/guardme` warning details screen. Model-facing follow-up guidance includes a `WARNINGS & DECISIONS` block with the reason and relevant matched rules. GuardMe refuses to save allow rules for hard-denied actions, refuses to persist command rules containing secret-like values, validates loaded JSONL state enums before using records, skips project-local policy/settings/state until the project is trusted, refuses symlinked or oversized policy/settings/state reads, refuses policy and runtime-settings writes that would follow symbolic links out of the expected config path, and refuses generated state writes through project-local state symlinks.

## `/guardme` General pane

`/guardme` opens on General. The first row toggles GuardMe between `active` and `off`; disabling requires confirmation and writes `.pi/agent/guardme-settings.json`, while enabling writes the same project-local setting without an extra confirmation. When GuardMe is off in a trusted project, guarded tool calls bypass GuardMe enforcement for that project. In an untrusted project, the setting is saved but ignored until project trust is enabled.

The second row toggles **Insecure edits**. Enabling requires confirmation because `write` and `edit` will skip proposed content/script scanning. This is useful for authoring scripts that contain commands GuardMe should still block at execution time, but path protections, deny rules, and credential paths still apply. `bash`, `read`, `grep`, `find`, and `ls` remain guarded, so running a generated local script is still inspected and can be blocked. Disabling Insecure edits restores normal write/edit content scanning without a confirmation.

The `Pi project trust` row writes Pi's saved project trust through Pi's trust store. This writes Pi’s project trust and may enable other project-local Pi resources after reload/restart. GuardMe reloads local policy, runtime settings, and state for the current session with the chosen trust value, but Pi project-local resources may require a restart or reload to fully reflect the new saved trust decision. `Warned fingerprints` and `Diagnostics` open human-readable detail screens; `Esc` returns to General. The Policies pane shows the resolved approval mode and its global-policy → project-policy → environment precedence.

## Examples

Global base policy:

```yaml
version: 1
approvalMode: auto

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
