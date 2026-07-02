const SECRET_ASSIGNMENT_PATTERN = /(\b[A-Za-z_][A-Za-z0-9_]*\s*=\s*)("[^"]*"|'[^']*'|[^\s"']+)/gi;
const AUTHORIZATION_BEARER_PATTERN = /(Authorization:\s*Bearer\s+)[^\s]+/gi;
const SECRET_FLAG_PATTERN = /(^|\s)(--?[A-Za-z][A-Za-z0-9_-]*(?:=|\s+))("[^"]*"|'[^']*'|[^\s"']+)/gi;

const SECRET_NAME_MARKERS = ["token", "secret", "password", "pass", "key"] as const;
const SECRET_FLAG_NAMES = new Set(["apikey", "accesskey", "clientsecret", "token", "secret", "password", "passwd", "pass"]);

export function redactSensitiveText(value: string): string {
  return value
    .replace(SECRET_ASSIGNMENT_PATTERN, redactSecretAssignment)
    .replace(AUTHORIZATION_BEARER_PATTERN, "$1<redacted>")
    .replace(SECRET_FLAG_PATTERN, redactSecretFlag);
}

function redactSecretAssignment(match: string, prefix: string): string {
  const name = prefix.slice(0, prefix.indexOf("=")).trim().toLowerCase();
  return SECRET_NAME_MARKERS.some((marker) => name.includes(marker)) ? `${prefix}<redacted>` : match;
}

function redactSecretFlag(match: string, leadingWhitespace: string, prefix: string): string {
  return SECRET_FLAG_NAMES.has(normalizeFlagName(prefix)) ? `${leadingWhitespace}${prefix}<redacted>` : match;
}

function normalizeFlagName(prefix: string): string {
  const flagName = prefix.trim().split("=", 1)[0] ?? "";
  return flagName.replaceAll("-", "").replaceAll("_", "").toLowerCase();
}
