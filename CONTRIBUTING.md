# Contributing

GuardMe is currently a prepared Pi extension project with implementation pending. Please read `docs/PROJECT_DEFINITION_BRIEF.md` and the specs under `specs/` before making feature changes.

## Development setup

GuardMe requires Node.js `>=22.19.0`.

```bash
npm install
npm run validate
```

Useful commands:

```bash
npm run typecheck
npm run test
npm run check:pack
pi --no-extensions -e .
```

## Implementation workflow

- Implement the task spec one checkbox at a time.
- Keep every task checkbox unchecked until its behavior, tests, and docs are complete.
- Keep `src/extension.ts` small; put policy/config/state/UI logic in focused modules.
- Update README/docs when commands, policy semantics, config paths, or security behavior change.
- Run `pi --no-extensions -e .` for isolated smoke testing.

## Pull requests

- Keep changes focused and explain user-visible behavior.
- Update tests for policy precedence, hard denials, and config/state behavior.
- Update README/docs/examples when behavior changes.
- Run `npm run validate` before requesting review, or explain why it could not be run.
- Do not commit secrets, local `.pi/` state, GuardMe state JSONL, generated reports, package tarballs, `node_modules/`, or machine-local paths.

## Security expectations

GuardMe is security-sensitive but not an OS sandbox. Treat changes that execute shell commands, read files, write files, persist policy, parse paths, or inspect credentials as security-sensitive and document the behavior.
