#!/usr/bin/env node
import { accessSync, constants as fsConstants, readFileSync } from "node:fs";
import { execFileSync, spawnSync } from "node:child_process";
import { createInterface } from "node:readline/promises";
import { argv, env as processEnv, execPath, platform, stdin as input, stdout as output } from "node:process";
import { delimiter, dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const rootUrl = new URL("../", import.meta.url);
const root = fileURLToPath(rootUrl);
const packageJsonUrl = new URL("package.json", rootUrl);
const rawPackageJson = JSON.parse(readFileSync(packageJsonUrl, "utf8"));
const semverPattern = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const packageNameSegmentPattern = /^[a-z0-9][a-z0-9._~-]*$/;
const gitBranchPattern = /^[A-Za-z0-9][A-Za-z0-9._/-]*$/;

export const SAFE_CHILD_PATH = [dirname(execPath), "/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin"].join(delimiter);

const GIT_EXECUTABLE_CANDIDATES = ["/opt/homebrew/bin/git", "/usr/local/bin/git", "/usr/bin/git", "/bin/git"];
const NPM_EXECUTABLE_CANDIDATES = [resolve(dirname(execPath), npmExecutableName()), "/opt/homebrew/bin/npm", "/usr/local/bin/npm", "/usr/bin/npm"];
let cachedGitExecutable;
let cachedNpmExecutable;

const pkg = validatePackageMetadata(rawPackageJson);

export function createChildEnv(sourceEnv = processEnv) {
  return {
    ...sourceEnv,
    PATH: SAFE_CHILD_PATH,
  };
}

function npmExecutableName() {
  return platform === "win32" ? "npm.cmd" : "npm";
}

function gitExecutablePath() {
  cachedGitExecutable ??= fixedExecutablePath("git", GIT_EXECUTABLE_CANDIDATES);
  return cachedGitExecutable;
}

function npmExecutablePath() {
  cachedNpmExecutable ??= fixedExecutablePath("npm", NPM_EXECUTABLE_CANDIDATES);
  return cachedNpmExecutable;
}

function fixedExecutablePath(commandName, candidates) {
  const executable = candidates.find(isExecutablePath);
  if (!executable) {
    throw new Error(`Unable to find ${commandName} executable in fixed system locations.`);
  }
  return executable;
}

function isExecutablePath(candidate) {
  try {
    accessSync(candidate, fsConstants.X_OK);
    return true;
  } catch {
    return false;
  }
}

export function validateVersionInput(version) {
  if (typeof version !== "string") {
    throw new TypeError("Version must be a string.");
  }
  const trimmed = version.trim();
  if (trimmed !== version || !semverPattern.test(trimmed)) {
    throw new Error("Enter a valid semver version, for example 0.1.1 or 1.0.0-beta.1.");
  }
  return trimmed;
}

export function validatePackageName(name) {
  if (typeof name !== "string") {
    throw new TypeError("package.json name must be a string.");
  }
  if (name.length === 0 || name.length > 214) {
    throw new Error("package.json name must be between 1 and 214 characters.");
  }
  if (name !== name.trim() || /[\s\u0000-\u0008\u000E-\u001F\u007F]/u.test(name)) {
    throw new Error("package.json name must not contain whitespace or control characters.");
  }
  if (name !== name.toLowerCase()) {
    throw new Error("package.json name must be lowercase for npm publishing.");
  }

  const segments = name.startsWith("@") ? scopedPackageSegments(name) : [name];
  for (const segment of segments) {
    if (!packageNameSegmentPattern.test(segment) || segment.startsWith(".") || segment.startsWith("_") || segment.startsWith("-") || segment.includes("..")) {
      throw new Error(`Unsafe npm package name: ${name}`);
    }
  }
  return name;
}

export function validatePackageMetadata(packageData) {
  if (!packageData || typeof packageData !== "object") {
    throw new Error("package.json must contain an object.");
  }
  return {
    ...packageData,
    name: validatePackageName(packageData.name),
    version: validateVersionInput(packageData.version),
  };
}

export function packageVersionSpecifier(packageName, version) {
  return `${validatePackageName(packageName)}@${validateVersionInput(version)}`;
}

export function validateGitBranchName(branch) {
  if (typeof branch !== "string") {
    throw new TypeError("Git branch name must be a string.");
  }
  if (branch.length === 0 || branch !== branch.trim() || !gitBranchPattern.test(branch)) {
    throw new Error(`Unsafe git branch name: ${branch}`);
  }
  if (branch.startsWith("-") || branch.endsWith(".") || branch.endsWith("/") || branch.includes("..") || branch.includes("//") || branch.includes("@{") || branch.includes("/.")) {
    throw new Error(`Unsafe git branch name: ${branch}`);
  }
  return branch;
}

function scopedPackageSegments(name) {
  const segments = name.split("/");
  if (segments.length !== 2 || !segments[0].startsWith("@") || segments[0].length === 1 || segments[1].length === 0) {
    throw new Error(`Unsafe npm package name: ${name}`);
  }
  return [segments[0].slice(1), segments[1]];
}

function captureGit(args, options = {}) {
  assertSafeCommandArgs(args);
  return execFileSync(gitExecutablePath(), args, {
    cwd: root,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
    ...options,
    env: createChildEnv(options.env ?? processEnv),
  }).trim();
}

function spawnGit(args, options = {}) {
  assertSafeCommandArgs(args);
  return spawnSync(gitExecutablePath(), args, {
    cwd: root,
    ...options,
    env: createChildEnv(options.env ?? processEnv),
  });
}

function spawnNpm(args, options = {}) {
  assertSafeCommandArgs(args);
  return spawnSync(npmExecutablePath(), args, {
    cwd: root,
    ...options,
    env: createChildEnv(options.env ?? processEnv),
  });
}

function runGit(args) {
  run("git", args, spawnGit);
}

function runNpm(args) {
  run("npm", args, spawnNpm);
}

function run(commandName, args, spawnCommand) {
  console.log(`\n$ ${formatCommandForLog(commandName, args)}`);
  const result = spawnCommand(args, { stdio: "inherit" });

  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}

function assertSafeCommandArgs(args) {
  if (!Array.isArray(args)) {
    throw new TypeError("Command arguments must be an array.");
  }
  for (const arg of args) {
    if (typeof arg !== "string" || arg.includes("\0")) {
      throw new Error("Command arguments must be strings without NUL characters.");
    }
  }
}

function formatCommandForLog(commandName, args) {
  return [commandName, ...args.map((arg) => JSON.stringify(arg))].join(" ");
}

function fail(message) {
  console.error(`\n${message}`);
  process.exit(1);
}

function gitCommandSucceeds(args) {
  const result = spawnGit(args, {
    stdio: "ignore",
  });
  return result.status === 0;
}

function ensureCleanGitTree() {
  const status = captureGit(["status", "--porcelain"]);
  if (status) {
    fail("Working tree is not clean. Commit or stash changes before publishing.");
  }
}

function ensureNpmLogin() {
  const result = spawnNpm(["whoami"], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });

  if (result.status !== 0) {
    fail("npm login is required before publishing. Run `npm login`, then retry.");
  }

  console.log(`npm user: ${String(result.stdout).trim()}`);
}

async function main() {
  console.log(`Publishing ${pkg.name}`);
  console.log(`Current version: ${pkg.version}`);

  ensureCleanGitTree();
  ensureNpmLogin();

  const rl = createInterface({ input, output });
  let version;
  try {
    version = validateVersionInput(await rl.question("Version to publish (for example 0.1.1): "));
  } catch (error) {
    rl.close();
    fail(error instanceof Error ? error.message : String(error));
  }

  if (version === pkg.version) {
    rl.close();
    fail(`package.json is already at version ${version}. Choose a new version.`);
  }

  const gitTag = `v${version}`;
  if (gitCommandSucceeds(["rev-parse", "--verify", `refs/tags/${gitTag}`])) {
    rl.close();
    fail(`Git tag ${gitTag} already exists.`);
  }

  const publishedVersion = spawnNpm(["view", packageVersionSpecifier(pkg.name, version), "version"], {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
  });

  if (publishedVersion.status === 0 && String(publishedVersion.stdout).trim()) {
    rl.close();
    fail(`${pkg.name}@${version} already exists on npm.`);
  }

  const publishArgs = ["publish"];
  if (pkg.name.startsWith("@")) {
    publishArgs.push("--access", "public");
  }

  console.log("\nThis will:");
  console.log("- run npm validation");
  console.log(`- run npm version ${version} to update package.json/package-lock.json`);
  console.log(`- create a release commit and git tag ${gitTag}`);
  console.log(`- run npm ${publishArgs.join(" ")}`);

  const confirm = (await rl.question("Continue? [y/N] ")).trim().toLowerCase();
  if (confirm !== "y" && confirm !== "yes") {
    rl.close();
    fail("Publish cancelled.");
  }

  rl.close();

  runNpm(["run", "validate"]);
  runNpm(["version", version, "-m", "chore(release): v%s"]);
  runNpm(publishArgs);

  const pushRl = createInterface({ input, output });
  const push = (await pushRl.question(`Push current branch and ${gitTag} to origin? [y/N] `)).trim().toLowerCase();
  pushRl.close();

  if (push === "y" || push === "yes") {
    const currentBranch = captureGit(["branch", "--show-current"]);
    if (!currentBranch) {
      fail(`Release was published, but git is in detached HEAD. Push ${gitTag} manually.`);
    }
    const branch = validateGitBranchName(currentBranch);

    runGit(["push", "origin", branch]);
    runGit(["push", "origin", gitTag]);
  }

  console.log(`\nPublished ${pkg.name}@${version}.`);
}

const modulePath = fileURLToPath(import.meta.url);
const invokedPath = argv[1] ? resolve(argv[1]) : undefined;
if (invokedPath === modulePath) {
  try {
    await main();
  } catch (error) {
    fail(error instanceof Error ? error.message : String(error));
  }
}
