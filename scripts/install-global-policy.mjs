#!/usr/bin/env node
import { access, lstat, mkdir, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { homedir } from "node:os";

import { createBuiltInDefaultPolicy } from "../src/config/schema.ts";
import { renderPolicyConfigYaml } from "../src/config/write-policy.ts";

const SKIP_VALUES = new Set(["1", "true", "yes"]);

if (SKIP_VALUES.has(String(process.env.GUARDME_SKIP_GLOBAL_POLICY_INSTALL ?? "").toLowerCase())) {
  process.exit(0);
}

const homeDir = resolve(process.env.GUARDME_HOME_DIR || homedir());
const policyPath = join(homeDir, ".pi", "agent", "guardme.yaml");

const unsafeExistingPath = await existingSymlinkInPath(policyPath);
if (unsafeExistingPath) {
  console.error(`Refusing to create GuardMe global policy through symbolic link: ${unsafeExistingPath}`);
  process.exit(1);
}

try {
  await access(policyPath);
  console.log(`GuardMe global policy already exists: ${policyPath}`);
  process.exit(0);
} catch {
  // Missing file is expected on first install.
}

const policyYaml = `# GuardMe global policy
# Created during GuardMe extension installation. Edit by hand or run /guardme.

${renderPolicyConfigYaml(createBuiltInDefaultPolicy())}`;

await mkdir(dirname(policyPath), { recursive: true });
const unsafeCreatedPath = await existingSymlinkInPath(policyPath);
if (unsafeCreatedPath) {
  console.error(`Refusing to create GuardMe global policy through symbolic link: ${unsafeCreatedPath}`);
  process.exit(1);
}
await writeFile(policyPath, policyYaml, { encoding: "utf8", flag: "wx", mode: 0o600 });
console.log(`Created GuardMe global policy: ${policyPath}`);

async function existingSymlinkInPath(targetPath) {
  const relativePath = relative(homeDir, resolve(targetPath));
  if (relativePath === "" || relativePath.startsWith("..") || isAbsolute(relativePath)) {
    return resolve(targetPath);
  }

  const segments = relativePath.split(sep).filter(Boolean);
  let current = homeDir;
  for (const segment of segments) {
    current = join(current, segment);
    try {
      const stats = await lstat(current);
      if (stats.isSymbolicLink()) {
        return current;
      }
    } catch (error) {
      if (error && typeof error === "object" && "code" in error && error.code === "ENOENT") {
        return undefined;
      }
      throw error;
    }
  }
  return undefined;
}
