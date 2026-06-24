import assert from "node:assert/strict";
import test from "node:test";

import { truncateToVisibleWidth, visibleWidth } from "../src/ui/text.ts";

test("ANSI-aware truncation preserves visible width without cutting escape sequences", () => {
  const red = "\u001B[31mabcdef\u001B[0m";
  const truncated = truncateToVisibleWidth(red, 4);

  assert.equal(visibleWidth(truncated), 4);
  assert.match(truncated, /^\u001B\[31mabc…/u);
  assert.doesNotMatch(truncated, /\u001B\[3…/u);
});

test("ANSI-aware truncation leaves short strings unchanged", () => {
  const value = "\u001B[1mok\u001B[0m";

  assert.equal(truncateToVisibleWidth(value, 2), value);
});
