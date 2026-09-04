const ENV_TEMPLATE_SUFFIXES = new Set(["example", "sample", "template", "dist"]);

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
  if (!lower.startsWith(".env.")) {
    return false;
  }
  return !ENV_TEMPLATE_SUFFIXES.has(lower.slice(lower.lastIndexOf(".") + 1));
}

// Word-boundary keyword match: "tokens.txt" and "my-secret.yaml" match, while
// "tokenizer.ts" and "secretary.md" do not.
export function containsCredentialKeyword(value: string): boolean {
  return /(?:credential|secret|token)s?(?![a-z0-9])/u.test(value.toLowerCase());
}
