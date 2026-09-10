import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

// The built-in policy allows the OS temp directory, so fixtures that must sit
// outside the project (or hold the project itself) cannot live under tmpdir().
// They go under the home cache and are removed when the test process exits.
const roots = [];
process.on("exit", () => {
  for (const root of roots) {
    rmSync(root, { recursive: true, force: true });
  }
});

export function outsideRoot(prefix = "guardme-outside-") {
  const base = join(homedir(), ".cache", "guardme-tests");
  mkdirSync(base, { recursive: true });
  const root = mkdtempSync(join(base, prefix));
  roots.push(root);
  return root;
}
