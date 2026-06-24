# GuardMe Structure Guide

GuardMe is a TypeScript Pi extension package. Runtime policy enforcement, approval UX, the `/guardme` configuration TUI, and validation guidance are implemented in `src/`, with the approved design retained in `docs/PROJECT_DEFINITION_BRIEF.md` and `specs/`.

## Prepared layout

```text
src/
├── extension.ts          # small entry point that wires register* modules
├── constants.ts          # GuardMe names, guarded tool names, config/state paths
├── commands/             # /guardme main/help command routing
├── events/               # lifecycle session loading, tool-call guard adapters, and guidance injection
├── config/               # YAML schema, default policy, config path resolution, merge/write logic
└── policy/               # pure domain types, path/command/script-content classification, and deny-first evaluation

specs/
├── spec-architecture.md  # architecture and data-flow plan
├── spec-guidelines.md    # engineering and security guidelines
└── spec-tasks.md         # unchecked implementation task plan
```

## Implementation layout

```text
src/
├── extension.ts          # only imports modules and calls register* functions
├── constants.ts          # display name, command name, status key, config/state paths
├── commands/             # /guardme main/help command routing
├── config/               # YAML schema, load/merge/write helpers
├── events/               # lifecycle, guidance, and tool_call handlers
├── policy/               # action classifiers, path matching, decision engine
├── state/                # JSONL warned-once state helpers
└── ui/                   # framed config TUI, approval prompt, setup wizard, policy summaries, and text helpers
```

## Pi surfaces

- Command: `/guardme` for General settings, setup, status, policies, rules, warning/decision details, diagnostic details, and project trust; `/guardme help` for compact usage.
- Events: `tool_call`, `before_agent_start`, `session_start`, and `session_shutdown`.
- UI: framed configuration TUI plus custom in-session approval prompt for repeated dangerous or policy-missing actions.
- Tools/resources: no new LLM-facing custom tools, skills, prompts, or themes.

## Implementation conventions

- Keep `src/extension.ts` small and free of policy logic.
- Do not start long-lived processes, file watchers, timers, sockets, or background jobs in the extension factory.
- Put pure policy/config/state logic in separate modules with unit tests.
- Use `tool_call` for Pi LLM tool-call enforcement.
- Fail closed when a dangerous action requires UI but no UI is available.
- Keep Pi core packages in `peerDependencies` with `"*"`.
- Add non-Pi runtime libraries to `dependencies` only when implementation imports them.

## Implementation boundary

The completed implementation tasks establish constants, registration boundaries, installer-created global defaults, Pi-independent policy domain types, config schema/default policy loading, global/local merge/write semantics with rule source metadata, safe path normalization/glob matching, conservative shell command classification, script-content extraction, the pure deny-first/default-deny policy evaluation engine, JSONL warned-once state helpers with reason codes and untrusted-project local-state skipping, project-local runtime settings for GuardMe active/off with trust-gated loading, session lifecycle loading/status cleanup, tool-call guard adapters for the approved built-in tools, first-dangerous/policy-missing-attempt coaching persistence, local script and package-manager script pre-execution inspection, approval UI/fallback handling, YAML rule persistence for saved decisions, model-facing follow-up guidance, a TUI setup wizard for defaults/custom rules, and `/guardme` main/help command UX.
