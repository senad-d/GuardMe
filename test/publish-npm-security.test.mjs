import assert from "node:assert/strict";
import test from "node:test";

import {
  SAFE_CHILD_PATH,
  createChildEnv,
  packageVersionSpecifier,
  validateGitBranchName,
  validatePackageMetadata,
  validatePackageName,
  validateVersionInput,
} from "../scripts/publish-npm.mjs";

test("publish helpers reject untrusted package and version inputs before command execution", () => {
  assert.equal(validatePackageName("@senad-d/guardme"), "@senad-d/guardme");
  assert.equal(validateVersionInput("1.2.3-beta.1"), "1.2.3-beta.1");
  assert.equal(packageVersionSpecifier("@senad-d/guardme", "1.2.3"), "@senad-d/guardme@1.2.3");

  assert.throws(() => validatePackageName("guardme; touch injected"), /package.*name|Unsafe npm package name/i);
  assert.throws(() => validatePackageName("@senad-d/guardme\nnext"), /package.*name|Unsafe npm package name/i);
  assert.throws(() => validatePackageName("-guardme"), /Unsafe npm package name/);
  assert.throws(() => validateVersionInput("1.2.3; rm -rf /"), /valid semver/);
  assert.throws(() => packageVersionSpecifier("guardme && npm publish", "1.2.3"), /package.*name|Unsafe npm package name/i);
});

test("publish metadata validation sanitizes package fields used in npm commands", () => {
  assert.deepEqual(validatePackageMetadata({ name: "guardme", version: "1.2.3", private: true }), {
    name: "guardme",
    version: "1.2.3",
    private: true,
  });

  assert.throws(() => validatePackageMetadata({ name: "guardme", version: "1.2.3 && npm publish" }), /valid semver/);
  assert.throws(() => validatePackageMetadata({ name: "guardme\u0000evil", version: "1.2.3" }), /package.*name/i);
});

test("publish helpers reject unsafe git branches before push", () => {
  assert.equal(validateGitBranchName("main"), "main");
  assert.equal(validateGitBranchName("feature/release-0.1.6"), "feature/release-0.1.6");

  assert.throws(() => validateGitBranchName("main; touch injected"), /Unsafe git branch name/);
  assert.throws(() => validateGitBranchName("--delete"), /Unsafe git branch name/);
  assert.throws(() => validateGitBranchName("feature/../main"), /Unsafe git branch name/);
  assert.throws(() => validateGitBranchName("feature branch"), /Unsafe git branch name/);
});

test("publish child processes receive a fixed safe PATH instead of inherited PATH", () => {
  const env = createChildEnv({ PATH: "/tmp/evil-bin", HOME: "/home/test-user", NPM_TOKEN: "test-token" });

  assert.equal(env.PATH, SAFE_CHILD_PATH);
  assert.doesNotMatch(env.PATH, /\/tmp\/evil-bin/);
  assert.equal(env.HOME, "/home/test-user");
  assert.equal(env.NPM_TOKEN, "test-token");
});
