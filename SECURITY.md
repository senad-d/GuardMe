# Security Policy

## Trust model

GuardMe is a Pi extension for checking LLM tool calls inside Pi sessions before they access shell commands or local files. It is not an OS sandbox, a kernel-level security boundary, or protection against commands run outside Pi.

Pi packages and extensions run with the full local permissions of the user account that starts Pi. Review extension source before installing it, pin versions in sensitive environments, and use containers, VMs, or OS-level sandboxing when you need stronger isolation.

## Protection scope

GuardMe guards LLM calls to these Pi built-in tools:

- `bash`
- `read`
- `write`
- `edit`
- `grep`
- `find`
- `ls`

Initial scope does not guard user-entered `!` / `!!` shell escapes, commands run outside Pi, arbitrary child processes outside Pi's tool path, or broader network/git policy. GuardMe now evaluates `bash` commands by executable segment and fails closed for segments that lack explicit command policy, but a user-approved command still runs with the local user's normal permissions.

## Hard-deny behavior

GuardMe denies these classes regardless of allow rules:

- cloud CLIs such as `aws`, `az`, and `gcloud`, including common command-wrapper, package-runner (`npx`, `npm exec`, `pnpm dlx`, `yarn dlx`, `bunx`), `env -C`/`-S`/`--split-string`, shell `-c` option variant, shell-substitution, command-separator, `find -exec`, ANSI-C quoted or line-continued command-name, dynamic shell-expanded command-name, inline interpreter, control-flow/grouping, and `eval`/`exec` forms
- disk formatting or raw disk operations
- deleting, moving, or renaming the `.git` directory or its contents, including broad destructive commands aimed at a parent directory
- credential-like path access, including case/glob-like variants such as `.SSH`, `.SSH*`, ambiguous `.env*` shell globs that could include `.env`, or `Secret.TXT`, broad `grep`/`find` discovery over directories with direct protected descendants, common shell read/copy/archive/redirection, generated script content, inline interpreter literal, and `dd if/of` forms
- reading or editing SSH keys
- `.env`, cloud credential directories, and credential-like files when protected by defaults or policy; `.env.example`-style templates are not hard-blocked unless policy denies them
- any action matching `zeroAccessPaths`
- mutations matching `readOnlyPaths`
- deletion/destructive move matching `noDeletePaths`

Deny rules always win over allow rules. Deny and dangerous command rules are evaluated against executable shell segments, absolute executable paths, local script content, package-manager script content, and common command-wrapper forms. Command allow rules are also segment-aware: wildcard rules can approve non-dangerous safe families such as `pwd *` or `ls *` only after path gates pass, while dangerous/delete/move/rename segments require exact approval. Command allow rules cannot approve outside-project path access unless a matching path rule permits the classified action, and broad wildcard allow rules cannot approve appended guarded segments or script content that fails policy. Policy-missing command segments are blocked first, then require user approval on repeat.

## Configuration and state

Policy files:

- global base: `~/.pi/agent/guardme.yaml`
- project overlay: `.pi/agent/guardme.yaml`

Generated `write`/`edit` payloads, local scripts, and package-manager scripts loaded from `package.json` may be inspected in memory before mutation or execution. GuardMe stores only redacted command labels, fingerprints, reason codes, reasons, and matched policy metadata; it must not store full generated file content, full policy files, or command output. Do not put secrets in policy rules.

Generated state files:

- global state: `~/.pi/agent/guardme-state.jsonl`
- project state: `.pi/agent/guardme-state.jsonl`

GuardMe does not run an npm lifecycle install script. Missing policy files are valid because built-in defaults apply at runtime; global and project-local policy files are created only when the user saves a rule or runs `/guardme`. Project-local policy, runtime settings, and generated state are loaded only after project trust; untrusted-project warnings are recorded in global state for the active cwd. Policy, runtime settings, and state reads fail closed for symlinked GuardMe paths or oversized files. GuardMe refuses policy writes that would follow symbolic links out of the expected config path, writes policy YAML with owner-only permissions, and refuses to persist command rules containing secret-like values. Generated warning state must not contain command output or file contents, and GuardMe redacts common secret assignments, bearer tokens, and secret-like CLI flags before storing or displaying command text. Approval and command notifications strip terminal control sequences from untrusted text. State writes refuse project-local state symlinks, and loaded state records are validated before they affect warned-once behavior.

## Reporting vulnerabilities

Please report suspected security vulnerabilities privately by email: <senad.dizdarevic@proton.me>.

For non-sensitive issues, use the repository issue tracker:

<https://github.com/senad-d/GuardMe/issues>

Do not open public issues for security-sensitive reports that include exploit details, private repository contents, secrets, credentials, or local policy files.

## Secure development checklist

- Do not commit secrets, tokens, local `.pi/` state, GuardMe state files, or generated artifacts.
- Treat every file, shell, config, and credential-handling change as security-sensitive.
- Keep deny-first policy precedence covered by tests.
- Avoid starting background resources in the extension factory.
- Keep package contents minimal with `npm run check:pack`.
- Use isolated smoke tests with `pi --no-extensions -e .`.
