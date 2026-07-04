export function isShellIdentifier(value: string): boolean {
  if (!isShellIdentifierStart(value[0] ?? "")) {
    return false;
  }
  for (let index = 1; index < value.length; index += 1) {
    if (!isShellIdentifierPart(value[index] ?? "")) {
      return false;
    }
  }
  return true;
}

export function isShellIdentifierStart(character: string): boolean {
  return character === "_" || isAsciiLetter(character);
}

export function isShellIdentifierPart(character: string): boolean {
  return isShellIdentifierStart(character) || isAsciiDigit(character);
}

export function isAsciiLetter(character: string): boolean {
  const codePoint = character.codePointAt(0);
  return codePoint !== undefined && ((codePoint >= 65 && codePoint <= 90) || (codePoint >= 97 && codePoint <= 122));
}

export function isAsciiDigit(character: string): boolean {
  const codePoint = character.codePointAt(0);
  return codePoint !== undefined && codePoint >= 48 && codePoint <= 57;
}
