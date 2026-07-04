export function isUp(data: string): boolean {
  return data === "\u001B[A" || data === "k";
}

export function isDown(data: string): boolean {
  return data === "\u001B[B" || data === "j";
}

export function isEnter(data: string): boolean {
  return data === "\r" || data === "\n";
}

export function isEscape(data: string): boolean {
  const normalized = data.toLowerCase();
  return (
    data === "\u001B" ||
    normalized === "escape" ||
    normalized === "esc" ||
    /^\u001B\[27(?:;1)?(?::1)?u$/.test(data) ||
    data === "\u001B[27;1;27~"
  );
}

export function isTab(data: string): boolean {
  return data === "\t" || data === "tab";
}

export function isBackspace(data: string): boolean {
  return data === "\b" || data === "\u007F" || data === "backspace";
}

export function isPrintable(data: string): boolean {
  return data.length === 1 && data >= " " && data !== "\u007F";
}

export function isCtrlC(data: string): boolean {
  return data === "\u0003" || data.toLowerCase() === "ctrl+c";
}

export function isQuit(data: string): boolean {
  return data === "q" || data === "Q";
}
