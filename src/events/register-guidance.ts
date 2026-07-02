import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

import { renderMatchedRules } from "../ui/render-policy-summary.ts";
import { sanitizeTerminalText, stripAnsiEscapes } from "../ui/text.ts";
import { clearGuardMeGuidance, getGuardMeSessionState, type GuardMeGuidanceEvent } from "./session-store.ts";

/** Register GuardMe model-facing guidance hooks. */
export function registerGuidance(pi: ExtensionAPI): void {
  pi.on("before_agent_start", () => {
    const guidance = getGuardMeSessionState()?.lastGuidance;
    if (!guidance) {
      return;
    }

    const content = buildWarningsAndDecisionsMessage(guidance);

    clearGuardMeGuidance();
    return {
      message: {
        customType: "guardme-guidance",
        content,
        display: true,
      },
    };
  });
}

function buildWarningsAndDecisionsMessage(guidance: GuardMeGuidanceEvent): string {
  const matchedRules = renderMatchedRules(guidance.matchedRules);
  const lines = [
    "WARNINGS & DECISIONS",
    `GuardMe blocked the previous ${safeGuidanceText(guidance.toolName)}:${safeGuidanceText(guidance.action)} request (${safeGuidanceText(guidance.reasonCode ?? guidance.risk)}).`,
    guidance.target ? `Target: ${safeGuidanceText(guidance.target)}` : undefined,
    `Reason: ${safeGuidanceText(guidance.reason)}`,
    `Next step: ${safeGuidanceText(guidance.guidance)}`,
    "",
    "Matched rules:",
    ...matchedRules.map((rule) => `- ${safeGuidanceText(rule)}`),
  ].filter((line): line is string => line !== undefined);

  return safeMultilineText(lines.join("\n"));
}

function safeGuidanceText(value: string): string {
  return sanitizeTerminalText(value);
}

function safeMultilineText(value: string): string {
  return stripAnsiEscapes(value)
    .replaceAll(/\r\n?/g, "\n")
    .replaceAll(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g, " ")
    .trim();
}
