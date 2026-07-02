import assert from "node:assert/strict";
import test from "node:test";

import { sanitizeTuiText } from "./e2e/helpers/tui-capture.mjs";

test("sanitizeTuiText removes ANSI and terminal control characters while preserving text layout", () => {
  const escape = String.fromCharCode(0x1b);
  const bell = String.fromCharCode(0x07);
  const nul = String.fromCharCode(0x00);
  const deleteControl = String.fromCharCode(0x7f);

  const sanitized = sanitizeTuiText(`title\n${escape}[31mred${escape}[0m\tcolumn${escape}]0;ignored${bell}${nul}${deleteControl}`);

  assert.equal(sanitized, "title\nred\tcolumn");
});
