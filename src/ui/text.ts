const ESCAPE = "\u001B";
const ELLIPSIS = "…";

export function visibleWidth(value: string): number {
  let width = 0;
  for (let index = 0; index < value.length;) {
    const escape = readAnsiEscape(value, index);
    if (escape) {
      index = escape.endIndex;
      continue;
    }

    const codePoint = value.codePointAt(index);
    if (codePoint === undefined) {
      break;
    }
    const character = String.fromCodePoint(codePoint);
    width += characterWidth(character);
    index += character.length;
  }
  return width;
}

export function sanitizeTerminalText(value: string): string {
  return stripAnsiEscapes(String(value))
    .replace(/[\u0000-\u001F\u007F-\u009F]/g, " ")
    .trim();
}

export function stripAnsiEscapes(value: string): string {
  let output = "";
  for (let index = 0; index < value.length;) {
    const escape = readAnsiEscape(value, index);
    if (escape) {
      index = escape.endIndex;
      continue;
    }

    const codePoint = value.codePointAt(index);
    if (codePoint === undefined) {
      break;
    }
    const character = String.fromCodePoint(codePoint);
    output += character;
    index += character.length;
  }
  return output;
}

export function truncateToVisibleWidth(value: string, width: number): string {
  if (width <= 0) {
    return "";
  }
  if (visibleWidth(value) <= width) {
    return value;
  }

  const contentWidth = Math.max(0, width - visibleWidth(ELLIPSIS));
  let usedWidth = 0;
  let output = "";
  for (let index = 0; index < value.length;) {
    const escape = readAnsiEscape(value, index);
    if (escape) {
      output += escape.sequence;
      index = escape.endIndex;
      continue;
    }

    const codePoint = value.codePointAt(index);
    if (codePoint === undefined) {
      break;
    }
    const character = String.fromCodePoint(codePoint);
    const nextWidth = usedWidth + characterWidth(character);
    if (nextWidth > contentWidth) {
      break;
    }
    output += character;
    usedWidth = nextWidth;
    index += character.length;
  }

  return `${output}${ELLIPSIS}`;
}

export function truncateTailToVisibleWidth(value: string, width: number): string {
  if (width <= 0) {
    return "";
  }
  if (visibleWidth(value) <= width) {
    return value;
  }

  const ellipsisWidth = visibleWidth(ELLIPSIS);
  if (width <= ellipsisWidth) {
    return truncateToVisibleWidth(ELLIPSIS, width);
  }

  const contentWidth = width - ellipsisWidth;
  let usedWidth = 0;
  let output = "";
  const characters = Array.from(value);
  for (let index = characters.length - 1; index >= 0; index -= 1) {
    const character = characters[index]!;
    const nextWidth = usedWidth + characterWidth(character);
    if (nextWidth > contentWidth) {
      break;
    }
    output = `${character}${output}`;
    usedWidth = nextWidth;
  }

  return `${ELLIPSIS}${output}`;
}

function readAnsiEscape(value: string, startIndex: number): { readonly sequence: string; readonly endIndex: number } | undefined {
  if (value[startIndex] !== ESCAPE) {
    return undefined;
  }

  const introducer = value[startIndex + 1];
  if (introducer === "[") {
    return readControlSequenceEscape(value, startIndex);
  }
  if (introducer === "]") {
    return readOperatingSystemCommandEscape(value, startIndex);
  }
  return introducer ? { sequence: value.slice(startIndex, startIndex + 2), endIndex: startIndex + 2 } : undefined;
}

function readControlSequenceEscape(value: string, startIndex: number): { readonly sequence: string; readonly endIndex: number } | undefined {
  for (let index = startIndex + 2; index < value.length; index += 1) {
    const code = value.codePointAt(index);
    if (code !== undefined && code >= 0x40 && code <= 0x7e) {
      return { sequence: value.slice(startIndex, index + 1), endIndex: index + 1 };
    }
  }
  return undefined;
}

function readOperatingSystemCommandEscape(value: string, startIndex: number): { readonly sequence: string; readonly endIndex: number } | undefined {
  for (let index = startIndex + 2; index < value.length; index += 1) {
    const terminator = oscTerminatorEndIndex(value, index);
    if (terminator !== undefined) {
      return { sequence: value.slice(startIndex, terminator), endIndex: terminator };
    }
  }
  return undefined;
}

function oscTerminatorEndIndex(value: string, index: number): number | undefined {
  if (value[index] === "\u0007") {
    return index + 1;
  }
  if (value[index] === ESCAPE && value[index + 1] === "\\") {
    return index + 2;
  }
  return undefined;
}

function characterWidth(character: string): number {
  return /\p{Mark}/u.test(character) ? 0 : 1;
}
