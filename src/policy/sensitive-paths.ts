const ENV_TEMPLATE_SUFFIXES = new Set(["example", "sample", "template", "dist"]);
// Code is named after what it handles (`token-cursor.js`, `.env.local.ts`), not after a secret it stores.
const SOURCE_FILE_NAME = /\.(?:[cm]?[jt]s|[jt]sx)$/u;

export function hasGlobWildcard(segment: string): boolean {
  return segment.includes("*") || segment.includes("?") || segment.includes("[") || segment.includes("]");
}

/**
 * `.env`-family file name segments that may hold real secrets: `.env`,
 * non-template variants such as `.env.local` or `.env.production`, and
 * ambiguous globbed forms such as `.env*`. Template names such as
 * `.env.example` are excluded so starter files stay editable.
 */
export function isProtectedEnvFileSegment(segment: string): boolean {
  const lower = segment.toLowerCase();
  if (lower === ".env") {
    return true;
  }
  if (!lower.startsWith(".env")) {
    return false;
  }
  if (hasGlobWildcard(lower)) {
    return true;
  }
  if (!lower.startsWith(".env.") || SOURCE_FILE_NAME.test(lower)) {
    return false;
  }
  return !ENV_TEMPLATE_SUFFIXES.has(lower.slice(lower.lastIndexOf(".") + 1));
}

// Word-boundary keyword match: "tokens.txt" and "my-secret.yaml" match, while
// "tokenizer.ts" and "secretary.md" do not. A source file's own name is not
// judged ("backward-token-cursor.js"); the directories above it still are.
export function containsCredentialKeyword(value: string): boolean {
  const lower = value.toLowerCase();
  const judged = SOURCE_FILE_NAME.test(lower) ? lower.slice(0, lower.replaceAll("\\", "/").lastIndexOf("/") + 1) : lower;
  return /(?:credential|secret|token)s?(?![a-z0-9])/u.test(judged);
}
