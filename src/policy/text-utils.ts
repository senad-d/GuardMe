export type CharacterPredicate = (character: string) => boolean;

export function splitByCharacter(value: string, isSeparator: CharacterPredicate): string[] {
  const parts: string[] = [];
  let current = "";
  for (const character of value) {
    if (isSeparator(character)) {
      if (current !== "") {
        parts.push(current);
        current = "";
      }
      continue;
    }
    current += character;
  }
  if (current !== "") {
    parts.push(current);
  }
  return parts;
}

export function collapseByCharacter(value: string, isSeparator: CharacterPredicate): string {
  return splitByCharacter(value, isSeparator).join(" ");
}
