# Test check registry

Check commands and scopes only; see [VALIDATION.md](VALIDATION.md) for the validation workflow and E2E setup.

| Check command | Scope |
| --- | --- |
| `node --test --test-reporter=dot test/tool-guard.test.mjs` | `src/events/register-guidance.ts`, `register-guard.ts`, and session state: custom-run preservation, exactly-once user/legacy delivery, no pending guidance, and redaction/sanitization after repeated visible or hidden custom runs; tool enforcement and approvals. |
