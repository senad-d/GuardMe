import { isAbsolute, join } from "node:path";
import { fileURLToPath } from "node:url";

export interface CurlFileAccess {
  readonly reads: readonly string[];
  readonly writes: readonly string[];
  readonly reviewReason?: string;
}

interface CurlScanState {
  reads: string[];
  writes: string[];
  outputs: string[];
  outputDirectory?: string;
  reviewReason?: string;
}

type CurlOptionKind = "read" | "write" | "output" | "data" | "form" | "header" | "cookie" | "url" | "config" | "directory" | "ignore";

const LONG_OPTIONS: Readonly<Record<string, CurlOptionKind>> = {
  "--output": "output", "--upload-file": "read", "--data": "data", "--data-ascii": "data",
  "--data-binary": "data", "--data-urlencode": "data", "--json": "data", "--form": "form",
  "--header": "header", "--proxy-header": "header", "--cookie": "cookie", "--cookie-jar": "write",
  "--dump-header": "write", "--trace": "write", "--trace-ascii": "write", "--stderr": "write",
  "--cert": "read", "--key": "read", "--cacert": "read", "--capath": "read", "--crlfile": "read",
  "--proxy-cert": "read", "--proxy-key": "read", "--proxy-cacert": "read", "--proxy-capath": "read",
  "--proxy-crlfile": "read", "--pinnedpubkey": "read", "--proxy-pinnedpubkey": "read",
  "--netrc-file": "read", "--random-file": "read", "--egd-file": "read", "--unix-socket": "read",
  "--hsts": "write", "--alt-svc": "write", "--etag-save": "write", "--etag-compare": "read",
  "--libcurl": "write", "--ssl-sessions": "write", "--knownhosts": "read", "--time-cond": "read",
  "--config": "config", "--output-dir": "directory", "--url": "url",
  "--data-raw": "ignore", "--form-string": "ignore", "--request": "ignore", "--user": "ignore",
  "--proxy-user": "ignore", "--proxy": "ignore", "--user-agent": "ignore", "--referer": "ignore",
  "--write-out": "header", "--connect-timeout": "ignore", "--max-time": "ignore", "--retry": "ignore",
  "--retry-delay": "ignore", "--retry-max-time": "ignore", "--max-redirs": "ignore", "--range": "ignore",
  "--continue-at": "ignore", "--limit-rate": "ignore", "--speed-limit": "ignore", "--speed-time": "ignore",
  "--resolve": "ignore", "--connect-to": "ignore", "--proto": "ignore", "--proto-redir": "ignore",
  "--url-query": "data", "--variable": "data",
};

const SHORT_OPTIONS: Readonly<Record<string, string>> = {
  o: "--output", T: "--upload-file", d: "--data", F: "--form", H: "--header", b: "--cookie",
  c: "--cookie-jar", D: "--dump-header", K: "--config", E: "--cert", A: "--user-agent",
  e: "--referer", u: "--user", U: "--proxy-user", x: "--proxy", X: "--request", w: "--write-out",
  m: "--max-time", r: "--range", C: "--continue-at", Y: "--speed-limit", y: "--speed-time", z: "--time-cond",
};

const DERIVED_OUTPUT_OPTIONS = new Set(["--remote-name", "--remote-name-all", "--remote-header-name"]);
const IMPLICIT_INPUT_OPTIONS = new Set(["--netrc", "--netrc-optional"]);

/** Inspect explicit local I/O only. Network policy belongs to a separate layer. */
export function curlFileAccess(args: readonly string[]): CurlFileAccess {
  const state: CurlScanState = { reads: [], writes: [], outputs: [] };
  let afterOptions = false;
  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index] ?? "";
    if (!afterOptions && arg === "--") {
      afterOptions = true;
    } else if (!afterOptions && arg.startsWith("--")) {
      index += scanLongOption(arg, args[index + 1], state);
    } else if (!afterOptions && arg.startsWith("-") && arg !== "-") {
      index += scanShortOptions(arg, args[index + 1], state);
    } else {
      addLocalUrl(arg, state);
    }
  }
  for (const output of state.outputs) {
    addCurlPath(state.writes, state.outputDirectory && !isAbsolute(output) ? join(state.outputDirectory, output) : output, state);
  }
  return { reads: [...new Set(state.reads)], writes: [...new Set(state.writes)], ...(state.reviewReason ? { reviewReason: state.reviewReason } : {}) };
}

function scanLongOption(arg: string, next: string | undefined, state: CurlScanState): number {
  const equals = arg.indexOf("=");
  const option = equals < 0 ? arg : arg.slice(0, equals);
  noteIndirectOption(option, state);
  const kind = Object.hasOwn(LONG_OPTIONS, option) ? LONG_OPTIONS[option] : undefined;
  if (!kind) {
    if (option.startsWith("--expand-") || option === "--next") {
      state.reviewReason = "curl expanded options or multiple transfer groups require explicit review of local file access.";
    }
    return 0;
  }
  const value = equals < 0 ? next : arg.slice(equals + 1);
  if (value === undefined) {
    state.reviewReason = `curl option ${option} is missing its argument.`;
  } else {
    applyCurlOption(option, kind, value, state);
  }
  return equals < 0 && next !== undefined ? 1 : 0;
}

function scanShortOptions(arg: string, next: string | undefined, state: CurlScanState): number {
  for (let index = 1; index < arg.length; index += 1) {
    const flag = arg[index] ?? "";
    if (flag === "O" || flag === "J") {
      noteIndirectOption("--remote-name", state);
    } else if (flag === "n") {
      noteIndirectOption("--netrc", state);
    } else if (flag === ":") {
      noteIndirectOption("--next", state);
      state.reviewReason = "curl multiple transfer groups require explicit review of local file access.";
    }
    const option = Object.hasOwn(SHORT_OPTIONS, flag) ? SHORT_OPTIONS[flag] : undefined;
    if (!option) {
      continue;
    }
    const attached = arg.slice(index + 1);
    const value = attached || next;
    if (value === undefined) {
      state.reviewReason = `curl option -${flag} is missing its argument.`;
    } else {
      applyCurlOption(option, LONG_OPTIONS[option]!, value, state);
    }
    return !attached && next !== undefined ? 1 : 0;
  }
  return 0;
}

function noteIndirectOption(option: string, state: CurlScanState): void {
  if (DERIVED_OUTPUT_OPTIONS.has(option)) {
    state.reviewReason = "curl derives output filenames from remote data; an exact allowCommands rule or user approval is required.";
  } else if (IMPLICIT_INPUT_OPTIONS.has(option)) {
    addCurlPath(state.reads, "~/.netrc", state);
  }
}

function applyCurlOption(option: string, kind: CurlOptionKind, value: string, state: CurlScanState): void {
  switch (kind) {
    case "read":
      addReadOptionFile(option, value, state);
      return;
    case "write":
      addCurlPath(state.writes, value, state);
      return;
    case "output":
      if (value !== "-") state.outputs.push(value);
      return;
    case "directory":
      state.outputDirectory = value;
      addCurlPath(state.writes, value, state);
      return;
    case "config":
      addCurlPath(state.reads, value, state);
      state.reviewReason = "curl configuration can introduce additional file access; an exact allowCommands rule or user approval is required.";
      return;
    case "data":
      addDataFile(option, value, state);
      return;
    case "form":
      addFormFiles(value, state);
      return;
    case "header":
      addHeaderOptionFile(option, value, state);
      return;
    case "cookie":
      if (!value.includes("=")) addCurlPath(state.reads, value, state);
      return;
    case "url":
      addLocalUrl(value, state);
      return;
    case "ignore":
      return;
  }
}

function addReadOptionFile(option: string, value: string, state: CurlScanState): void {
  if (option.includes("pinnedpubkey") && value.startsWith("sha256//")) {
    return;
  }
  const path = option.endsWith("cert") && !option.endsWith("cacert") ? value.split(":")[0] ?? value : value;
  addCurlPath(state.reads, path, state);
}

function addHeaderOptionFile(option: string, value: string, state: CurlScanState): void {
  if (value.startsWith("@")) {
    addCurlPath(state.reads, value.slice(1), state);
  }
  if (option === "--write-out" && (value.includes("%output{") || value.includes("%{stderr}"))) {
    state.reviewReason = "curl write-out output routing requires explicit review of local file access.";
  }
}

function addDataFile(option: string, value: string, state: CurlScanState): void {
  if (value.startsWith("@")) {
    addCurlPath(state.reads, value.slice(1), state);
  } else if (["--data-urlencode", "--url-query", "--variable"].includes(option)) {
    const at = value.indexOf("@");
    if (at >= 0 && !value.slice(0, at).includes("=")) {
      addCurlPath(state.reads, value.slice(at + 1), state);
    }
  }
}

function addFormFiles(value: string, state: CurlScanState): void {
  const equals = value.indexOf("=");
  const payload = value.slice(equals + 1);
  if (equals < 0 || (!payload.startsWith("@") && !payload.startsWith("<"))) {
    return;
  }
  if (/["\\]/u.test(payload)) {
    state.reviewReason = "curl quoted multipart filenames require explicit review of local file access.";
  }
  for (const file of payload.slice(1).split(",")) {
    addCurlPath(state.reads, file.split(";")[0] ?? file, state);
  }
}

function addLocalUrl(value: string, state: CurlScanState): void {
  if (!/^file:/iu.test(value)) {
    return;
  }
  try {
    addCurlPath(state.reads, fileURLToPath(value), state);
  } catch {
    state.reviewReason = "curl local file URL could not be resolved safely.";
  }
}

function addCurlPath(paths: string[], value: string, state: CurlScanState): void {
  if (value === "-" || value === "") {
    return;
  }
  if (/[\n\r$`*?{}[\]]/u.test(value)) {
    state.reviewReason = "curl dynamic or globbed file operands require explicit review of local file access.";
  }
  paths.push(value);
}
