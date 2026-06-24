const SECRET_ASSIGNMENT_PATTERN = /([A-Za-z_][A-Za-z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASS|KEY)[A-Za-z0-9_]*\s*=\s*)("[^"]*"|'[^']*'|[^\s"']+)/gi;
const AUTHORIZATION_BEARER_PATTERN = /(Authorization:\s*Bearer\s+)[^\s]+/gi;
const SECRET_FLAG_PATTERN = /((?:--?)(?:api[-_]?key|access[-_]?key|client[-_]?secret|token|secret|password|passwd|pass)(?:=|\s+))("[^"]*"|'[^']*'|[^\s"']+)/gi;

export function redactSensitiveText(value: string): string {
  return value
    .replace(SECRET_ASSIGNMENT_PATTERN, "$1<redacted>")
    .replace(AUTHORIZATION_BEARER_PATTERN, "$1<redacted>")
    .replace(SECRET_FLAG_PATTERN, "$1<redacted>");
}
