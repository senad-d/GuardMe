import assert from "node:assert/strict";
import test from "node:test";

import { renderMainRow } from "../src/ui/config-frame.ts";

test("frame value rows right-align values in a stable column", () => {
  const width = 60;
  const rows = [
    renderMainRow({ kind: "value", label: "Protected policy files", value: 2 }, width),
    renderMainRow({ kind: "value", label: "Secret and credential paths", value: 17 }, width),
    renderMainRow({ kind: "value", label: "TOTAL", value: 45 }, width),
  ];

  for (const row of rows) {
    assert.equal(row.length, width);
  }
  assert.equal(rows[0].endsWith("2"), true);
  assert.equal(rows[1].endsWith("17"), true);
  assert.equal(rows[2].endsWith("45"), true);
});
