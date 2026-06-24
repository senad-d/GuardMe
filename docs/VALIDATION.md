# GuardMe Validation

Run the repository checks before publishing or handing off GuardMe changes:

```bash
npm run typecheck
npm run test
npm run check:pack
npm run format:check
npm run validate
```

Global-policy helper smoke test:

```bash
GUARDME_HOME_DIR="$(mktemp -d)" node scripts/install-global-policy.mjs
```

Isolated extension-load smoke test:

```bash
pi --no-extensions -e . --offline --no-tools --no-session -p ""
```

The command above loads only this checkout as an explicit extension, disables discovered extensions and tools, avoids network startup work, and exits without contacting a model.

Local-only e2e suite (not part of `npm test` or CI):

```bash
npm run test:e2e:rpc   # Starts Pi RPC with GuardMe and a deterministic scripted provider
npm run test:e2e:tui   # Generates the /guardme text capture artifact
npm run test:e2e       # Runs both local e2e checks
```

The RPC e2e suite uses disposable `/tmp/guardme-e2e-*` project and HOME directories, loads GuardMe via `-e`, and uses a network-free `guardme-e2e/scripted` provider. No real LLM API key or cloud credentials are required. Every RPC e2e run writes inspectable artifacts under `tmp/e2e/`, including `guardme-rpc-summary.md`, JSONL events/stdout/UI requests, stderr, final policy YAML, state JSONL, and runtime settings. The TUI capture writes a sanitized review artifact to `tmp/e2e/guardme-tui-panels.txt`; `tmp/` is ignored by git.

Manual/interactive smoke scenarios for TUI sessions:

1. Allowed project read succeeds (`read` on a normal project file).
2. Protected `.env` read blocks.
3. `aws sts get-caller-identity` blocks as a hard-denied cloud CLI.
4. Cloud CLIs also block when hidden behind shell substitutions, command separators, shell grouping/control flow, ANSI-C quoted or line-continued command names, dynamic shell-expanded command names, inline interpreter calls, `eval`/`exec`, prefix wrappers such as `sudo -u` or `command -p`, package runners such as `npx`, `npm exec`, `pnpm dlx`, `yarn dlx`, or `bunx`, `env -C`/`-S`/`--split-string`, shell `-c` option variants, or command wrappers such as escaped/multiple `find -exec`, `xargs`, `watch`, `timeout`, or `nice`.
5. Credential-like shell operands block through common read/copy/archive commands, input redirection such as `grep token < ~/.aws/credentials`, inline interpreter literals, `dd if/of`, and ambiguous glob forms such as `cat .env*`; exact `.env.example` template paths remain editable unless policy denies them.
6. First `rm -rf build`-style dangerous attempt blocks with coaching and records JSONL warning state.
7. Repeated dangerous attempt opens approval UI in TUI/RPC-capable modes and fails closed without UI.
8. `/guardme` opens on General; toggling GuardMe off requires confirmation, writes `.pi/agent/guardme-settings.json`, and allows a normally blocked guarded action until toggled active again in a trusted project.
9. `/guardme` General shows Insecure edits directly below GuardMe; enabling it requires confirmation, writes `.pi/agent/guardme-settings.json`, allows `write`/`edit` to author scripts with otherwise blocked commands, and still blocks `bash ./script.sh` when the script content fails policy.
10. In an untrusted project, `/guardme` can save the active/off and Insecure edits settings but explains that project-local settings apply only after project trust is enabled.
11. `/guardme` can update the Pi project trust row through Pi's saved trust store, with the expected reload/restart note.
12. `/guardme` opens human-readable warning/decision and diagnostic detail screens, and `Esc` returns to General.
13. `/guardme` can create global/local defaults and custom rules through the framed Setup and Confirm flow.
14. Saving a local/global approval writes the expected GuardMe YAML rule and refuses symlinked project config paths.
15. In an untrusted project, project-local policy/settings/state is skipped and warned-once state is recorded globally for that cwd.
16. Oversized or malformed project runtime settings fail safe to active and report diagnostics.
17. Unsupported policy versions report diagnostics and do not apply their rules.
18. Malformed, empty, or path-incompatible path rule `actions` values report diagnostics and do not become broad allow rules.
19. Approval modals and `/guardme` notifications strip terminal control sequences from untrusted command, path, rule, and command-argument text.
20. Outside-project read without allow policy blocks.
21. Outside-project read with explicit `readOnlyPaths`/`allowPaths` succeeds.
22. Outside-project mutation remains denied unless explicitly allowed and not protected.
23. Segment-aware starter allows such as `pwd *` and `ls *` allow `pwd && ls -lh`, while `pwd && unknown-tool` blocks as policy-missing and names the missing segment.
24. Broad validation command allows such as `npm test*` do not approve appended guarded segments, for example `npm test && rm -rf build`, `npm test && cat /etc/passwd`, or wrapped denied commands such as `env -- sudo ls`.
25. Deny command rules catch absolute executable paths and slash-containing arguments, for example `/usr/bin/sudo ls`, `sudo /bin/ls`, `/usr/bin/sudoedit /etc/hosts`, and `chmod 777 /tmp/file`.
26. Broad `grep`/`ggrep`/`find` discovery over a directory containing direct protected descendants blocks, including absolute executable paths and discovery segments appended to another command; direct built-in `grep`/`find` with a safe `glob`/pattern remains allowed, and constrained `bash` commands such as `find . -name '*.ts'` may run only when their command segment is allowed.
27. Broad destructive shell commands aimed at a directory containing protected metadata block, for example `find . -delete` when `.git` is present or `rm -rf vendor` when a nested `vendor/module/.git` is present.
28. Exact command allows for compound commands do not approve outside-project path access; for example `rm -rf build && cat /etc/passwd` still blocks instead of turning the outside read into an approved destructive command.
29. Writing or editing a command-bearing script that invokes `.env`, `~/.aws`, `~/.azure`, SSH keys, cloud CLIs, dangerous commands, or unknown commands blocks before mutation while Insecure edits is off.
30. Running a local script such as `./audit.sh` or `bash audit.sh` inspects the script before execution and blocks when the script content fails policy.
31. Running package-manager scripts such as `npm test`, `npm run test`, `pnpm run build`, `yarn test`, or `bun run test` inspects the relevant `package.json` script and matching `pre*`/`post*` scripts, including cwd/prefix variants such as `npm --prefix packages/app test`, `npm test --prefix packages/app`, `pnpm -C packages/app run build`, `yarn --cwd packages/app test`, and `bun --cwd packages/app run test`; cloud CLIs, credential reads, dangerous commands, and outside-project path access inside those scripts block before execution.
32. Generic browser/GUI launchers such as `brave ...` or `open -a Brave ...` block as policy-missing on first attempt and require approval on repeat.
