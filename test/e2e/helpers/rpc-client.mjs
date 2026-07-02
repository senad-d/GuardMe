import { spawn } from "node:child_process";
import { StringDecoder } from "node:string_decoder";
import { env as processEnv, execPath } from "node:process";
import { fileURLToPath } from "node:url";
import { delimiter, dirname, join, resolve } from "node:path";

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(HERE, "../../..");
const SCRIPTED_PROVIDER = join(REPO_ROOT, "test", "e2e", "fixtures", "scripted-provider.ts");
const PI_CLI_PATH = join(REPO_ROOT, "node_modules", "@earendil-works", "pi-coding-agent", "dist", "cli.js");
const DEFAULT_TIMEOUT_MS = 60_000;

export const SAFE_RPC_PATH = [
  dirname(execPath),
  join(REPO_ROOT, "node_modules", ".bin"),
  "/opt/homebrew/bin",
  "/usr/local/bin",
  "/usr/bin",
  "/bin",
].join(delimiter);

export function createRpcChildEnv(options, sourceEnv = processEnv) {
  return {
    ...sourceEnv,
    HOME: options.homeDir,
    PI_CODING_AGENT_DIR: join(options.homeDir, ".pi", "agent"),
    PI_OFFLINE: "1",
    PI_SKIP_VERSION_CHECK: "1",
    PI_TELEMETRY: "0",
    NO_COLOR: "1",
    PATH: SAFE_RPC_PATH,
  };
}

export function createRpcSpawnCommand(args) {
  return { command: execPath, args: [PI_CLI_PATH, ...args] };
}

export async function startRpcPi(options) {
  const client = new RpcPiClient(options);
  await client.start();
  await client.send({ type: "get_state" }, { timeoutMs: 30_000 });
  return client;
}

export class RpcPiClient {
  constructor(options) {
    this.options = {
      repoRoot: REPO_ROOT,
      providerPath: SCRIPTED_PROVIDER,
      timeoutMs: DEFAULT_TIMEOUT_MS,
      ...options,
    };
    this.events = [];
    this.responses = [];
    this.uiRequests = [];
    this.stderr = "";
    this.stdoutLines = [];
    this.pending = new Map();
    this.eventWaiters = [];
    this.nextId = 1;
    this.activeUiHandler = undefined;
    this.proc = undefined;
    this.exit = undefined;
  }

  async start() {
    const args = [
      "--mode",
      "rpc",
      "--no-extensions",
      "-e",
      this.options.repoRoot,
      "-e",
      this.options.providerPath,
      "--provider",
      "guardme-e2e",
      "--model",
      "scripted",
      "--tools",
      "read,bash,edit,write,grep,find,ls",
      "--offline",
      "--no-session",
      "--approve",
    ];

    const spawnCommand = createRpcSpawnCommand(args);
    this.proc = spawn(spawnCommand.command, spawnCommand.args, {
      cwd: this.options.projectDir,
      env: createRpcChildEnv(this.options),
      stdio: ["pipe", "pipe", "pipe"],
    });

    this.proc.stdout.on("data", createJsonlChunkHandler((line) => this.handleStdoutLine(line)));
    this.proc.stderr.on("data", (chunk) => {
      this.stderr += chunk.toString("utf8");
    });
    this.proc.on("exit", (code, signal) => {
      this.exit = { code, signal };
      const error = new Error(`pi rpc exited code=${code ?? "null"} signal=${signal ?? "null"}\n${this.stderrTail()}`);
      for (const pending of this.pending.values()) {
        pending.reject(error);
      }
      this.pending.clear();
      for (const waiter of this.eventWaiters.splice(0)) {
        waiter.reject(error);
      }
    });
  }

  async send(command, options = {}) {
    if (!this.proc?.stdin.writable) {
      throw new Error(`pi rpc stdin is not writable. ${this.stderrTail()}`);
    }

    const id = command.id ?? `e2e-${this.nextId++}`;
    const payload = { ...command, id };
    const timeoutMs = options.timeoutMs ?? this.options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const responsePromise = new Promise((resolvePromise, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`Timed out waiting for RPC response ${id} (${command.type}).\n${this.stderrTail()}`));
      }, timeoutMs);
      this.pending.set(id, {
        resolve: (response) => {
          clearTimeout(timer);
          resolvePromise(response);
        },
        reject: (error) => {
          clearTimeout(timer);
          reject(error);
        },
      });
    });

    this.proc.stdin.write(`${JSON.stringify(payload)}\n`);
    const response = await responsePromise;
    if (!response.success) {
      throw new Error(`RPC ${response.command ?? command.type} failed: ${response.error ?? "unknown error"}\n${this.stderrTail()}`);
    }
    return response;
  }

  async prompt(message, options = {}) {
    return this.withUiHandler(options.uiHandler, async () => {
      const eventStart = this.events.length;
      const uiStart = this.uiRequests.length;
      const response = await this.send({ type: "prompt", message }, { timeoutMs: options.timeoutMs });
      if (options.settleMs !== 0) {
        await sleep(options.settleMs ?? 250);
      }
      return {
        response,
        events: this.events.slice(eventStart),
        uiRequests: this.uiRequests.slice(uiStart),
      };
    });
  }

  async promptAndWaitForAgentEnd(message, options = {}) {
    return this.withUiHandler(options.uiHandler, async () => {
      const eventStart = this.events.length;
      const uiStart = this.uiRequests.length;
      const response = await this.send({ type: "prompt", message }, { timeoutMs: options.timeoutMs });
      await this.waitForEvent((event, index) => index >= eventStart && event.type === "agent_end", options.timeoutMs ?? this.options.timeoutMs);
      await this.waitForIdle(options.timeoutMs ?? this.options.timeoutMs);
      return {
        response,
        events: this.events.slice(eventStart),
        uiRequests: this.uiRequests.slice(uiStart),
      };
    });
  }

  respondToExtensionUi(id, response) {
    if (!this.proc?.stdin.writable) {
      throw new Error("pi rpc stdin is not writable");
    }
    this.proc.stdin.write(`${JSON.stringify({ type: "extension_ui_response", id, ...response })}\n`);
  }

  async waitForIdle(timeoutMs = DEFAULT_TIMEOUT_MS) {
    const deadline = Date.now() + timeoutMs;
    let idleStreak = 0;
    while (Date.now() < deadline) {
      const response = await this.send({ type: "get_state" }, { timeoutMs: Math.min(5_000, timeoutMs) });
      const state = response.data ?? {};
      if (!state.isStreaming && !state.isCompacting && (state.pendingMessageCount ?? 0) === 0) {
        idleStreak += 1;
        if (idleStreak >= 2) {
          return;
        }
      } else {
        idleStreak = 0;
      }
      await sleep(100);
    }
    throw new Error(`Timed out waiting for RPC idle state. ${this.stderrTail()}`);
  }

  waitForEvent(predicate, timeoutMs = DEFAULT_TIMEOUT_MS) {
    for (let index = 0; index < this.events.length; index += 1) {
      const event = this.events[index];
      if (predicate(event, index)) {
        return Promise.resolve(event);
      }
    }

    return new Promise((resolvePromise, reject) => {
      const waiter = {
        predicate,
        resolve: (event) => {
          clearTimeout(timer);
          resolvePromise(event);
        },
        reject: (error) => {
          clearTimeout(timer);
          reject(error);
        },
      };
      const timer = setTimeout(() => {
        const waiterIndex = this.eventWaiters.indexOf(waiter);
        if (waiterIndex >= 0) {
          this.eventWaiters.splice(waiterIndex, 1);
        }
        reject(new Error(`Timed out waiting for RPC event. ${this.stderrTail()}`));
      }, timeoutMs);
      this.eventWaiters.push(waiter);
    });
  }

  async stop() {
    if (!this.proc || this.exit) {
      return;
    }
    const proc = this.proc;
    await new Promise((resolvePromise) => {
      const timer = setTimeout(() => {
        proc.kill("SIGKILL");
        resolvePromise();
      }, 2_000);
      proc.once("exit", () => {
        clearTimeout(timer);
        resolvePromise();
      });
      proc.kill("SIGTERM");
    });
  }

  stderrTail(max = 4_000) {
    return this.stderr.length > max ? this.stderr.slice(-max) : this.stderr;
  }

  async withUiHandler(handler, callback) {
    const previous = this.activeUiHandler;
    this.activeUiHandler = handler;
    try {
      return await callback();
    } finally {
      this.activeUiHandler = previous;
    }
  }

  handleStdoutLine(line) {
    if (!line.trim()) {
      return;
    }
    this.stdoutLines.push(line);
    const message = this.parseStdoutMessage(line);
    if (!message) {
      return;
    }
    if (this.resolveResponseMessage(message)) {
      return;
    }
    if (this.dispatchUiRequestMessage(message)) {
      return;
    }
    this.recordEventMessage(message);
  }

  parseStdoutMessage(line) {
    try {
      return JSON.parse(line);
    } catch (error) {
      const parseError = new Error(`Invalid RPC JSON line: ${line}\n${error instanceof Error ? error.message : String(error)}`);
      this.rejectPendingRequests(parseError);
      return undefined;
    }
  }

  rejectPendingRequests(error) {
    for (const pending of this.pending.values()) {
      pending.reject(error);
    }
    this.pending.clear();
  }

  resolveResponseMessage(message) {
    if (message.type !== "response") {
      return false;
    }
    this.responses.push(message);
    const pending = this.pending.get(message.id);
    if (pending) {
      this.pending.delete(message.id);
      pending.resolve(message);
    }
    return true;
  }

  dispatchUiRequestMessage(message) {
    if (message.type !== "extension_ui_request") {
      return false;
    }
    this.uiRequests.push(message);
    void this.handleUiRequest(message).catch((error) => {
      this.stderr += `\n[guardme-e2e ui handler error] ${error instanceof Error ? error.stack ?? error.message : String(error)}\n`;
      if (isDialogMethod(message.method)) {
        this.respondToExtensionUi(message.id, { cancelled: true });
      }
    });
    return true;
  }

  recordEventMessage(message) {
    const index = this.events.length;
    this.events.push(message);
    if (message.type === "extension_error") {
      const error = new Error(`Extension error from ${message.extensionPath ?? "unknown"}: ${message.error ?? "unknown"}`);
      this.rejectEventWaiters(error);
      this.rejectPendingRequests(error);
      return;
    }
    this.resolveMatchingEventWaiters(message, index);
  }

  rejectEventWaiters(error) {
    for (const waiter of this.eventWaiters.splice(0)) {
      waiter.reject(error);
    }
  }

  resolveMatchingEventWaiters(message, eventIndex) {
    let waiterIndex = 0;
    while (waiterIndex < this.eventWaiters.length) {
      const waiter = this.eventWaiters[waiterIndex];
      if (waiter.predicate(message, eventIndex)) {
        this.eventWaiters.splice(waiterIndex, 1);
        waiter.resolve(message);
        continue;
      }
      waiterIndex += 1;
    }
  }

  async handleUiRequest(request) {
    if (!isDialogMethod(request.method)) {
      return;
    }

    const result = this.activeUiHandler ? await this.activeUiHandler(request, this) : undefined;
    this.respondToExtensionUi(request.id, normalizeUiResponse(request, result));
  }
}

export function createSetupUiHandler() {
  return (request) => {
    if (request.method === "select") {
      return request.options?.find((option) => option.startsWith("Create project policy with sensible defaults")) ?? request.options?.[0];
    }
    if (request.method === "confirm") {
      return true;
    }
    return undefined;
  };
}

export function createApprovalUiHandler(labelPrefix) {
  return (request) => {
    if (request.method !== "select") {
      return undefined;
    }
    return request.options?.find((option) => option.startsWith(labelPrefix));
  };
}

export function toolExecutionEnds(events, toolName) {
  return events.filter((event) => event.type === "tool_execution_end" && (!toolName || event.toolName === toolName));
}

export function lastToolExecutionEnd(events, toolName) {
  const ends = toolExecutionEnds(events, toolName);
  return ends.at(-1);
}

export function resultText(resultOrEvent) {
  const result = resultOrEvent?.result ?? resultOrEvent;
  return (result?.content ?? [])
    .map((block) => (block && typeof block.text === "string" ? block.text : ""))
    .join("\n");
}

export function eventsText(events) {
  return events.map((event) => JSON.stringify(event)).join("\n");
}

function createJsonlChunkHandler(onLine) {
  const decoder = new StringDecoder("utf8");
  let buffer = "";
  return (chunk) => {
    buffer += typeof chunk === "string" ? chunk : decoder.write(chunk);
    while (true) {
      const newlineIndex = buffer.indexOf("\n");
      if (newlineIndex < 0) {
        break;
      }
      let line = buffer.slice(0, newlineIndex);
      buffer = buffer.slice(newlineIndex + 1);
      if (line.endsWith("\r")) {
        line = line.slice(0, -1);
      }
      onLine(line);
    }
  };
}

function normalizeUiResponse(request, result) {
  if (result && typeof result === "object" && !Array.isArray(result)) {
    return result;
  }
  if (result === undefined || result === null) {
    return { cancelled: true };
  }
  if (request.method === "confirm") {
    return { confirmed: Boolean(result) };
  }
  return { value: String(result) };
}

function isDialogMethod(method) {
  return method === "select" || method === "confirm" || method === "input" || method === "editor";
}

function sleep(ms) {
  return new Promise((resolvePromise) => setTimeout(resolvePromise, ms));
}
