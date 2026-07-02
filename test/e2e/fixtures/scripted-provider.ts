import { resolve } from "node:path";

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

const PROVIDER = "guardme-e2e";
const MODEL = "scripted";
const API = "guardme-e2e-scripted";
const SCENARIO_PATTERN = /SCENARIO:\s*([a-z0-9-]+)/i;

let toolCallCounter = 0;

export default async function scriptedProvider(pi: ExtensionAPI): Promise<void> {
  const { createAssistantMessageEventStream } = await loadPiAi();

  pi.registerProvider(PROVIDER, {
    name: "GuardMe E2E Scripted Provider",
    baseUrl: "http://127.0.0.1/guardme-e2e-scripted",
    apiKey: "guardme-e2e-scripted-no-network",
    api: API,
    models: [
      {
        id: MODEL,
        name: "GuardMe E2E Scripted",
        reasoning: false,
        input: ["text"],
        cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
        contextWindow: 128000,
        maxTokens: 4096,
      },
    ],
    streamSimple: (model: any, context: any, options: any) => {
      const stream = createAssistantMessageEventStream();
      queueMicrotask(async () => {
        await options?.onResponse?.({ status: 200, headers: {} }, model);
        if (options?.signal?.aborted) {
          const aborted = createAssistantMessage(model, [], "aborted", "Request was aborted");
          stream.push({ type: "error", reason: "aborted", error: aborted });
          stream.end(aborted);
          return;
        }

        const response = responseForContext(context);
        await streamAssistantResponse(stream, model, response);
      });
      return stream;
    },
  });
}

async function loadPiAi(): Promise<{ createAssistantMessageEventStream: () => any }> {
  try {
    return (await import("@earendil-works/pi-ai")) as { createAssistantMessageEventStream: () => any };
  } catch {
    return (await import(
      new URL("../../../node_modules/@earendil-works/pi-coding-agent/node_modules/@earendil-works/pi-ai/dist/index.js", import.meta.url).href
    )) as { createAssistantMessageEventStream: () => any };
  }
}

function responseForContext(context: any): ScriptedResponse {
  const latest = context.messages?.at(-1);
  if (latest?.role === "toolResult") {
    return { kind: "text", text: `SCENARIO TOOL RESULT RECEIVED: ${latest.toolName}` };
  }

  const scenario = latestScenarioName(context);
  if (!scenario) {
    return { kind: "text", text: "GuardMe e2e scripted provider idle." };
  }

  const toolCall = toolCallForScenario(scenario);
  if (!toolCall) {
    return { kind: "text", text: `Unknown GuardMe e2e scenario: ${scenario}` };
  }
  return { kind: "tool", scenario, toolCall };
}

function latestScenarioName(context: any): string | undefined {
  for (const message of [...(context.messages ?? [])].reverse()) {
    const scenario = SCENARIO_PATTERN.exec(contentToText(message?.content))?.[1];
    if (scenario) {
      return scenario;
    }
  }
  return undefined;
}

function contentToText(content: unknown): string {
  if (typeof content === "string") {
    return content;
  }
  if (Array.isArray(content)) {
    return content.map((block) => (block && typeof block === "object" && "text" in block ? String((block as any).text) : "")).join("\n");
  }
  return "";
}

interface ScriptedToolCall {
  readonly name: string;
  readonly arguments: Record<string, unknown>;
}

type ScriptedResponse =
  | { readonly kind: "text"; readonly text: string }
  | { readonly kind: "tool"; readonly scenario: string; readonly toolCall: ScriptedToolCall };

function outsideFixturePath(directoryName: "outside-read" | "outside-write" | "outside-delete"): string {
  return resolve(process.cwd(), "..", directoryName, "file.txt");
}

function shellQuote(value: string): string {
  return `'${value.replaceAll("'", String.raw`'\''`)}'`;
}

function toolCallForScenario(scenario: string): ScriptedToolCall | undefined {
  switch (scenario) {
    case "allowed-read":
      return { name: "read", arguments: { path: "README.md" } };
    case "allowed-validation-command":
      return { name: "bash", arguments: { command: "npm test -- --help" } };
    case "allowed-write":
      return { name: "write", arguments: { path: "tmp/safe-write.txt", content: "safe write from guardme e2e\n" } };
    case "allowed-edit":
      return { name: "edit", arguments: { path: "notes.txt", edits: [{ oldText: "original safe note\n", newText: "edited safe note\n" }] } };
    case "allowed-find-scoped":
      return { name: "find", arguments: { path: ".", pattern: "*.md" } };
    case "protected-env-read":
      return { name: "read", arguments: { path: ".env" } };
    case "hard-deny-cloud-cli":
      return { name: "bash", arguments: { command: "aws sts get-caller-identity" } };
    case "hard-deny-cloud-cli-wrapper":
      return { name: "bash", arguments: { command: "env -S \"aws sts get-caller-identity\"" } };
    case "broad-discovery-protected-descendant":
      return { name: "grep", arguments: { path: ".", pattern: "GUARDME_E2E_FAKE_TOKEN" } };
    case "broad-find-protected-descendant":
      return { name: "find", arguments: { path: ".", pattern: "*" } };
    case "hard-deny-env-delete":
      return { name: "bash", arguments: { command: "rm -rf .env" } };
    case "protected-metadata-delete":
      return { name: "bash", arguments: { command: "rm -rf .git" } };
    case "outside-read-block":
      return { name: "read", arguments: { path: outsideFixturePath("outside-read") } };
    case "outside-read-allowed":
      return { name: "read", arguments: { path: outsideFixturePath("outside-read") } };
    case "outside-write-block":
      return { name: "write", arguments: { path: outsideFixturePath("outside-write"), content: "outside changed by guardme e2e\n" } };
    case "outside-delete-block":
      return { name: "bash", arguments: { command: `rm -rf ${shellQuote(outsideFixturePath("outside-delete"))}` } };
    case "command-allow-boundary":
      return { name: "bash", arguments: { command: "npm test -- --help && rm -rf build" } };
    case "script-write-denied-content":
      return {
        name: "write",
        arguments: { path: "scripts/generated-unsafe.sh", content: "#!/bin/sh\ncat .env\n" },
      };
    case "script-edit-denied-content":
      return {
        name: "edit",
        arguments: { path: "scripts/safe.sh", edits: [{ oldText: "echo safe\n", newText: "aws sts get-caller-identity\n" }] },
      };
    case "local-script-exec-denied-content":
      return { name: "bash", arguments: { command: "bash scripts/unsafe.sh" } };
    case "policy-missing-generic-command":
      return { name: "bash", arguments: { command: "awk 'BEGIN { print \"guardme generic\" }'" } };
    case "approval-dangerous-delete":
      return { name: "bash", arguments: { command: "rm -rf approval-target/file.txt" } };
    case "approval-dangerous-deny":
      return { name: "bash", arguments: { command: "rm -rf deny-target/file.txt" } };
    default:
      return undefined;
  }
}

async function streamAssistantResponse(stream: any, model: any, response: ScriptedResponse): Promise<void> {
  if (response.kind === "text") {
    const message = createAssistantMessage(model, [{ type: "text", text: response.text }], "stop");
    stream.push({ type: "start", partial: { ...message, content: [] } });
    stream.push({ type: "text_start", contentIndex: 0, partial: { ...message, content: [{ type: "text", text: "" }] } });
    stream.push({ type: "text_delta", contentIndex: 0, delta: response.text, partial: message });
    stream.push({ type: "text_end", contentIndex: 0, content: response.text, partial: message });
    stream.push({ type: "done", reason: "stop", message });
    stream.end(message);
    return;
  }

  const id = `guardme-e2e-${response.scenario}-${++toolCallCounter}`;
  const toolCall = { type: "toolCall", id, name: response.toolCall.name, arguments: response.toolCall.arguments };
  const message = createAssistantMessage(model, [toolCall], "toolUse");
  const argsJson = JSON.stringify(response.toolCall.arguments);
  const partial = { ...message, content: [{ type: "toolCall", id, name: response.toolCall.name, arguments: {} }] };
  stream.push({ type: "start", partial: { ...message, content: [] } });
  stream.push({ type: "toolcall_start", contentIndex: 0, partial });
  stream.push({ type: "toolcall_delta", contentIndex: 0, delta: argsJson, partial });
  partial.content[0].arguments = response.toolCall.arguments;
  stream.push({ type: "toolcall_end", contentIndex: 0, toolCall, partial: message });
  stream.push({ type: "done", reason: "toolUse", message });
  stream.end(message);
}

function createAssistantMessage(model: any, content: any[], stopReason: "stop" | "toolUse" | "error" | "aborted", errorMessage?: string): any {
  return {
    role: "assistant",
    content,
    api: model.api ?? API,
    provider: model.provider ?? PROVIDER,
    model: model.id ?? MODEL,
    usage: {
      input: 0,
      output: 0,
      cacheRead: 0,
      cacheWrite: 0,
      totalTokens: 0,
      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
    },
    stopReason,
    ...(errorMessage ? { errorMessage } : {}),
    timestamp: Date.now(),
  };
}
