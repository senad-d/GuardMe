import assert from "node:assert/strict";
import test from "node:test";

import { redactSensitiveText } from "../src/policy/redact.ts";

test("redacts secret assignments, bearer tokens, and secret flags", () => {
  const redacted = redactSensitiveText(
    "get-caller-identity --token secret-value API_KEY=abc Authorization: Bearer bearer-value --file safe.txt",
  );

  assert.equal(
    redacted,
    "get-caller-identity --token <redacted> API_KEY=<redacted> Authorization: Bearer <redacted> --file safe.txt",
  );
});

test("redaction keeps long non-secret hyphenated text from consuming later secret flags", () => {
  const longHyphenatedName = `tool ${"caller-".repeat(5000)}identity`;
  const redacted = redactSensitiveText(`${longHyphenatedName} --client-secret 'secret-value' --label visible`);

  assert.equal(redacted.includes(`${longHyphenatedName} --client-secret <redacted>`), true);
  assert.equal(redacted.endsWith("--label visible"), true);
});
