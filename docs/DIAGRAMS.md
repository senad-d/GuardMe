# GuardMe visual guide

Two diagrams explain the safety gate and what happens after a warning. Both are embedded in the [README](../README.md), with text equivalents below. The diagrams are static so branches can be compared at a glance, including with reduced-motion preferences; the existing [demo GIF](../img/demo.gif) shows the interactive UI.

## 1. Tool-call safety gate

[View full-size PNG](../img/diagrams/guardme-tool-call-enforcement.png) · [Editable draw.io source](../img/diagrams/guardme-tool-call-enforcement.drawio)

**Reading the diagram:** follow the solid arrows from the agent to GuardMe, then to the three outcomes. The dashed arrow supplies policy inputs rather than executing an action. Labels, not just colors, distinguish the outcomes.

1. **Pi proposes a tool call.** While active, GuardMe intercepts `tool_call` before a guarded tool executes. Built-ins are `bash`, `read`, `write`, `edit`, `grep`, `find`, and `ls`. Third-party tools require an explicit `guardedTools` mapping.
2. **Policy supplies the rules.** Built-in defaults combine with global `~/.pi/agent/guardme.yaml` and trusted project `.pi/agent/guardme.yaml`. Missing policy files are valid. Local allow rules do not override denials or protections. Project-local policy, settings and state are ignored until the project is trusted.
3. **GuardMe checks the action.** It resolves paths and their actions, enforces protections and outside-project permissions, checks shell segments and wrappers, and inspects local/package scripts and command-bearing file changes. This box groups the checks conceptually; it is not a literal execution-order diagram.
4. **The call is blocked, reviewed, or allowed.** Denials and missing required path permissions stop the call without an approval bypass. Eligible risky or policy-missing actions enter the warning/approval flow. Only after all applicable checks pass does GuardMe let Pi proceed with the tool; another extension may still block it.

Examples with built-in defaults and no additional policy:

| Proposed shell call | Result | Why |
| --- | --- | --- |
| `pwd && ls -lh` | Allow | Both executable segments are allowed and path checks pass. |
| `pwd && unknown-tool` | Warn / review | Allowing `pwd` does not allow the unknown segment. |
| `cat .env` | Block | A command allow cannot override credential-path protection. |

**Scope:** turning GuardMe off bypasses enforcement for a trusted project. Insecure edits skips only proposed `write`/`edit` content scanning, not path protections. Unmapped tools, user-entered `!` / `!!` shell commands, other processes, and LLM API traffic are outside this gate. GuardMe is not an OS sandbox or network filter. See [limitations](POLICY.md#limitations) and [security boundaries](../SECURITY.md).

## 2. Warning and approval flow

[View full-size PNG](../img/diagrams/guardme-approval-flow.png) · [Editable draw.io source](../img/diagrams/guardme-approval-flow.drawio)

**Reading the diagram:** the top row follows a new eligible fingerprint from warning to retry; the four branches compare alternative modes, not sequential steps. A fingerprint identifies the policy action, command and targets used to match a repeated request.

1. **First eligible attempt:** block without running the tool, record the warned fingerprint, and return safer-action guidance.
2. **Matching retry:** re-evaluate protections, then use the resolved approval mode if approval is still required. A changed request may have a different fingerprint. An already-loaded warning can enter at the retry step, except that `agent` mode always requires its own first in-process block.
3. **Resolve approval:** the mode controls whether a person can decide, the agent retry gate can authorize the action, or the call must stay blocked.

| Mode | Behavior for an approval-required retry |
| --- | --- |
| `auto` (default) | Ask in TUI when approval UI is available. RPC, JSON, print, unknown modes and missing UI fail closed. |
| `interactive` | Ask when the relevant approval UI is available. RPC requires a controller that handles `extension_ui_request` and responds with `extension_ui_response`. No UI means blocked. |
| `agent` (explicit opt-in) | Never prompt, even in TUI. Block the first in-process attempt and same-turn duplicates. An identical fingerprint in a later agent turn can receive automatic allow-once. |
| `block` | Never prompt or automatically approve an approval-required call. Already-allowed calls still proceed. |

Hard denials, explicit command/path denies, protected credentials/paths, and missing outside-project permissions are not approval candidates. Approval does not skip any remaining checks on the tool call.

**Human decisions:** allow or deny once, or save a narrow project/global rule. Cancellation means deny once. Saved rules reload policy; project rules require trust, and unsafe persistence (such as secret-bearing command rules) is refused. Missing UI does not invent a user decision or save an approval. Warnings and actual decisions are recorded in redacted JSONL state.

**Automatic decisions:** `agent` mode writes `automatic-decision` audit entries, never YAML rules. Dangerous actions need a new block/later-turn retry cycle for each use. An approved policy-missing command keeps a session-scoped allowance, with each reuse audited and protections still evaluated. Old warning state cannot arm the in-memory turn gate. A turn is one assistant response and its tool calls, not necessarily a new user message. Child processes are not automatically opted in.

**Mode precedence:** built-in `auto` → global YAML → trusted project YAML → process `GUARDME_APPROVAL_MODE`. Later sources override earlier modes; invalid values produce diagnostics and resolve to `block` for that source/override. This override behavior applies to the mode, not to deny-first policy rules.

See the [approval reference](POLICY.md#approval-modes) for full details.

## Editing and exporting

The `.drawio` files are the source of truth. The PNGs also embed editable diagram data and have an opaque white background for light and dark documentation themes. No new runtime dependency is needed.

1. Open the relevant `.drawio` file in diagrams.net / draw.io Desktop and edit the native shapes and connectors.
2. Keep text readable, outcomes explicitly labeled, and connectors clear of shapes. Enlarge cards and the canvas rather than reducing font sizes to fit more text.
3. With the Pi draw.io tools, run `drawio_validate` after each source edit. Use `drawio_fit_canvas` for page-margin issues, then validate again.
4. Run `drawio_check`, export a PNG with `drawio_export` in `preview` mode, and inspect text wrapping, margins, arrow direction and crossings. After fixes, validate and compare the replacement preview.
5. Export in `final` mode with scale `2`, border `30`, and embedded diagram data. Keep the final PNG at the basename linked above; do not retain preview artifacts. In the desktop export dialog, use the equivalent 200% zoom, 30px border, white background, and **Include a copy of my diagram** options.
6. Update the source, PNG and text walkthrough together when behavior changes. Check both README image links before publishing.

### Behavior references for maintainers

- Tool mapping, script/content inspection and decision handling: [`src/events/register-guard.ts`](../src/events/register-guard.ts)
- Deny-first evaluation and fingerprints: [`src/policy/evaluate.ts`](../src/policy/evaluate.ts)
- Policy merging and alias handling: [`src/config/merge-policy.ts`](../src/config/merge-policy.ts)
- Approval-mode environment override: [`src/config/approval-mode.ts`](../src/config/approval-mode.ts)
- UI availability and human choices: [`src/ui/approval-modal.ts`](../src/ui/approval-modal.ts)
- Process-local agent turn gate: [`src/events/session-store.ts`](../src/events/session-store.ts)
